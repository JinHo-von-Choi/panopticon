"""보안 쿠키와 일회용 전달로 OIDC 로그인을 콘솔에 연결한다."""

from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from netwatcher.web.auth import AuthStateUnavailable
from netwatcher.web.oidc import OidcTokenInvalid, OidcProviderUnavailable

BROWSER_COOKIE = '__Host-panopticon-oidc'
DELIVERY_COOKIE = '__Host-panopticon-oidc-delivery'
PRIVATE_HEADERS = {'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'}


def cookie(response, name, value, ttl):
    response.set_cookie(name, value, max_age=ttl, secure=True, httponly=True, samesite='lax', path='/')


def clear_cookies(response):
    for name in (BROWSER_COOKIE, DELIVERY_COOKIE):
        response.delete_cookie(name, secure=True, httponly=True, samesite='lax', path='/')
    return response


def create_oidc_router(login):
    router = APIRouter(prefix='/auth/oidc', tags=['auth'])
    origin = 'https://' + urlsplit(login.provider.redirect_uri).netloc if login is not None else None

    def same_origin(address):
        try:
            actual, expected = urlsplit(address), urlsplit(origin)
            return (actual.scheme, actual.hostname, actual.port or 443) == (expected.scheme, expected.hostname, expected.port or 443)
        except (TypeError, ValueError):
            return False

    def trusted_request(request):
        if login is None:
            return JSONResponse({'error': 'OIDC is disabled'}, 404, headers=PRIVATE_HEADERS)
        actual = request.url.scheme + '://' + request.url.netloc
        if not same_origin(actual):
            return JSONResponse({'error': 'Invalid console origin'}, 400, headers=PRIVATE_HEADERS)
        return None

    async def rate_limit(request, bucket):
        limiter = getattr(request.app.state, 'login_limiter', None)
        ip = request.client.host if request.client else 'unknown'
        if limiter is not None and not await limiter.check(bucket + ':' + ip):
            return JSONResponse({'error': 'Too many login attempts'}, 429,
                headers=PRIVATE_HEADERS | {'Retry-After': '60'})
        return None

    @router.get('/start')
    async def start(request: Request):
        refused = trusted_request(request)
        if refused is not None:
            return refused
        if request.headers.get('sec-fetch-site') == 'cross-site':
            return JSONResponse({'error': 'Invalid login origin'}, 403, headers=PRIVATE_HEADERS)
        refused = await rate_limit(request, 'login')
        if refused is not None:
            return refused
        try:
            pending = await login.begin()
        except (AuthStateUnavailable, OidcProviderUnavailable):
            return JSONResponse({'error': 'SSO login unavailable'}, 503, headers=PRIVATE_HEADERS)
        response = RedirectResponse(pending['url'], status_code=303, headers=PRIVATE_HEADERS)
        cookie(response, BROWSER_COOKIE, pending['browser'], 300)
        response.delete_cookie(DELIVERY_COOKIE, secure=True, httponly=True, samesite='lax', path='/')
        return response

    @router.get('/callback')
    async def callback(request: Request):
        query = request.query_params
        # 콜백 값은 읽은 뒤 접근 로그의 요청 주소에서 제거한다.
        request.scope['query_string'] = b''
        refused = trusted_request(request)
        if refused is not None:
            return refused
        refused = await rate_limit(request, 'oidc-callback')
        if refused is not None:
            return clear_cookies(refused)
        failed = clear_cookies(RedirectResponse(origin + '/?oidc=failed', 303, headers=PRIVATE_HEADERS))
        if (len(query.getlist('state')) != 1 or len(query.getlist('code')) != 1
                or 'error' in query or len(query.getlist('iss')) > 1
                or ('iss' in query and query['iss'] != login.provider.issuer)):
            return failed
        browser = request.cookies.get(BROWSER_COOKIE)
        try:
            token = await login.finish(state=query['state'], browser=browser, code=query['code'])
            ticket = await login.deliver(token, browser)
        except (AuthStateUnavailable, OidcProviderUnavailable, OidcTokenInvalid):
            return failed
        response = RedirectResponse(origin + '/?oidc=finish', 303, headers=PRIVATE_HEADERS)
        cookie(response, BROWSER_COOKIE, browser, 30)
        cookie(response, DELIVERY_COOKIE, ticket, 30)
        return response

    @router.post('/session')
    async def session(request: Request):
        refused = trusted_request(request)
        if refused is not None:
            return refused
        origins = request.headers.getlist('origin')
        if (len(origins) != 1 or not same_origin(origins[0])
                or urlsplit(origins[0]).path or urlsplit(origins[0]).query or urlsplit(origins[0]).fragment
                or urlsplit(origins[0]).username is not None or urlsplit(origins[0]).password is not None):
            return JSONResponse({'error': 'Invalid session origin'}, 403, headers=PRIVATE_HEADERS)
        refused = await rate_limit(request, 'oidc-session')
        if refused is not None:
            return clear_cookies(refused)
        try:
            token = await login.redeem(request.cookies.get(DELIVERY_COOKIE), request.cookies.get(BROWSER_COOKIE))
        except OidcTokenInvalid:
            return clear_cookies(JSONResponse({'error': 'SSO login failed'}, 401, headers=PRIVATE_HEADERS))
        except AuthStateUnavailable:
            return clear_cookies(JSONResponse({'error': 'SSO login unavailable'}, 503, headers=PRIVATE_HEADERS))
        return clear_cookies(JSONResponse({'token': token}, headers=PRIVATE_HEADERS))

    return router
