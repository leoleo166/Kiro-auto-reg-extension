"""
Kiro / AWS Builder ID 自动注册 v10 (纯协议, 无 Playwright)
v10 = v8 核心 + HAR 深度分析修复:
  ★ 核心修复: 移除 _setup_signin_js_cookies() 对服务端 cookie 的覆盖
    - workflow-csrf-token, directory-csrf-token 等由服务端 Set-Cookie 管理
    - 只有 platform-ubid 是 JS 生成的
  ★ _capture_cookies 修复: 有 Domain= 的 cookie 存储到裸域名, 避免重复
  ★ Step 4a 后从 workflow-csrf-token 提取 signupCsrfToken 更新 directory-csrf-token
pip install curl_cffi cbor2 jwcrypto
"""
import re,uuid,json,random,string,time,base64,hashlib,secrets
import struct,binascii,math
from urllib.parse import urlparse,parse_qs,quote as url_quote,urlencode,urljoin
import cbor2
from curl_cffi import requests as curl_requests
from jwcrypto import jwk, jwe

KIRO="https://app.kiro.dev"
SIGNIN="https://us-east-1.signin.aws"
DIR_ID="d-9067642ac7"
PROFILE="https://profile.aws.amazon.com"

OFFICIAL_STAGE_PROFILE_ARNS = {
    "social": {
        "beta": "arn:aws:codewhisperer:us-west-2:820242940701:profile/WM4CAQWR93QR",
        "gamma": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
        "prod": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
    },
    "builder_id": {
        "beta": "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX",
        "gamma": "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX",
        "prod": "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX",
    },
}

UA={
    "user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/146.0.0.0 Safari/537.36",
    "sec-ch-ua":'"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    "sec-ch-ua-mobile":"?0",
    "sec-ch-ua-platform":'"Windows"',
    "accept-language":"ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "accept-encoding":"gzip, deflate, br, zstd",
    "sec-fetch-site":"same-origin",
    "sec-fetch-mode":"cors",
    "sec-fetch-dest":"empty",
    "cache-control":"no-cache",
    "pragma":"no-cache",
    "priority":"u=1, i",
}
X_AMZ_UA = ("aws-sdk-js/1.0.0 ua/2.1 "
            "os/Windows lang/js md/browser#Google-Chrome_146 m/N,M,E")

# ═══ XXTEA ═══
XXTEA_KEY=[1888420705,2576816180,2347232058,874813317]
XXTEA_DELTA=0x9E3779B9
_u32=lambda x:x&0xFFFFFFFF

def _xxtea_enc(data_str, key):
    raw = data_str.encode("latin-1") if isinstance(data_str,str) else data_str
    while len(raw)%4!=0: raw+=b"\x00"
    n=len(raw)//4
    if n<2: raw+=b"\x00"*4; n=2
    v=list(struct.unpack(f"<{n}I",raw))
    rounds=6+52//n; s=v[n-1]; c=0
    for _ in range(rounds):
        c=_u32(c+XXTEA_DELTA); u=(c>>2)&3
        for d in range(n):
            nx=v[(d+1)%n]
            mx=_u32(_u32(_u32(s>>5)^_u32(nx<<2))+_u32(_u32(nx>>3)^_u32(s<<4)))
            mx=_u32(mx^_u32(_u32(c^nx)+_u32(key[(3&d)^u]^s)))
            v[d]=_u32(v[d]+mx); s=v[d]
    return b"".join(struct.pack("<I",x) for x in v)

def _gen_perf(nav_start):
    dns=nav_start+random.randint(30,40)
    conn=dns; ssl=dns
    conn_end=dns+random.randint(1,3)
    req=conn_end+random.randint(0,2)
    resp_s=req+random.randint(250,350)
    resp_e=resp_s
    dom_load=resp_e+random.randint(2,5)
    dom_int=dom_load+random.randint(2800,3500)
    dom_cl_s=dom_int; dom_cl_e=dom_int
    dom_comp=dom_cl_e+random.randint(800,1200)
    load_s=dom_comp; load_e=dom_comp
    return {"connectStart":conn,"secureConnectionStart":ssl,
        "unloadEventEnd":0,"domainLookupStart":dns,
        "domainLookupEnd":dns,"responseStart":resp_s,
        "connectEnd":conn_end,"responseEnd":resp_e,
        "requestStart":req,"domLoading":dom_load,
        "redirectStart":0,"loadEventEnd":load_e,
        "domComplete":dom_comp,"navigationStart":nav_start,
        "loadEventStart":load_s,
        "domContentLoadedEventEnd":dom_cl_e,
        "unloadEventStart":0,"redirectEnd":0,
        "domInteractive":dom_int,"fetchStart":dns,
        "domContentLoadedEventStart":dom_cl_s}

REAL_HIST=[13847,42,42,40,62,33,47,29,41,37,32,25,27,53,23,22,31,20,24,
30,34,20,37,15,21,32,25,26,66,25,16,27,26,19,22,32,38,15,39,35,49,9,29,
43,16,26,23,15,29,30,36,46,18,29,11,30,24,27,20,27,22,19,20,38,171,32,
25,33,15,15,6,22,11,39,31,24,18,12,17,34,17,30,17,27,25,28,20,19,19,19,
24,34,10,24,14,27,28,18,31,27,78,28,512,41,28,22,34,15,26,29,34,16,17,
21,17,43,17,9,24,34,17,14,26,6,20,39,28,25,230,20,44,19,8,24,18,12,28,
16,5,28,37,21,11,27,22,30,18,16,25,18,11,25,30,104,13,38,22,22,42,18,23,
22,32,9,30,18,5,31,34,18,24,17,22,25,12,16,34,18,28,23,15,55,45,18,21,
31,21,28,22,21,31,30,145,29,19,34,18,21,24,37,30,19,49,34,62,62,23,24,
21,40,27,30,37,22,38,51,40,37,29,27,53,28,31,27,37,36,40,57,31,22,41,32,
23,35,28,58,41,45,27,38,36,48,49,30,37,78,56,36,40,62,48,81,70,59,94,13740]

GPU_EXT=["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_clip_control",
"EXT_color_buffer_half_float","EXT_depth_clamp",
"EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth",
"EXT_polygon_offset_clamp","EXT_shader_texture_lod",
"EXT_texture_compression_bptc","EXT_texture_compression_rgtc",
"EXT_texture_filter_anisotropic","EXT_texture_mirror_clamp_to_edge",
"EXT_sRGB","KHR_parallel_shader_compile","OES_element_index_uint",
"OES_fbo_render_mipmap","OES_standard_derivatives","OES_texture_float",
"OES_texture_float_linear","OES_texture_half_float",
"OES_texture_half_float_linear","OES_vertex_array_object",
"WEBGL_blend_func_extended","WEBGL_color_buffer_float",
"WEBGL_compressed_texture_astc","WEBGL_compressed_texture_etc",
"WEBGL_compressed_texture_etc1","WEBGL_compressed_texture_pvrtc",
"WEBGL_compressed_texture_s3tc","WEBGL_compressed_texture_s3tc_srgb",
"WEBGL_debug_renderer_info","WEBGL_debug_shaders",
"WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context",
"WEBGL_multi_draw","WEBGL_polygon_mode"]

def gen_fwcim(location_url, ubid_main, canvas_hash=None):
    now_ms=int(time.time()*1000)
    nav_start=now_ms-random.randint(3500,5000)
    if canvas_hash is None: canvas_hash=random.randint(1000000000,2147483647)
    plugins=("PDF Viewer Chrome PDF Viewer Chromium PDF Viewer "
             "Microsoft Edge PDF Viewer WebKit built-in PDF "
             "||1440-900-900-30-*-*-*")
    data={
        "metrics":{"el":0,"script":0,"h":0,"batt":0,"perf":0,"auto":0,
            "tz":0,"fp2":0,"lsubid":1,"browser":0,"capabilities":0,
            "gpu":0,"dnt":0,"math":0,"tts":0,"input":0,"canvas":0,
            "captchainput":0,"pow":0},
        "start":now_ms-random.randint(20,60),
        "interaction":{"clicks":0,"touches":0,"keyPresses":0,"cuts":0,
            "copies":0,"pastes":0,"keyPressTimeIntervals":[],
            "mouseClickPositions":[],"keyCycles":[],"mouseCycles":[],
            "touchCycles":[]},
        "scripts":{"dynamicUrls":["/assets/js/app.js"],"inlineHashes":[],
            "elapsed":0,"dynamicUrlCount":1,"inlineHashesCount":0},
        "history":{"length":random.randint(2,8)},
        "battery":{},
        "performance":{"timing":_gen_perf(nav_start)},
        "automation":{"wd":{"properties":{"document":[],"window":[],
            "navigator":[]}},"phantom":{"properties":{"window":[]}}},
        "end":now_ms,
        "timeZone":8,
        "flashVersion":None,
        "plugins":plugins,"dupedPlugins":plugins,
        "screenInfo":"1440-900-900-30-*-*-*",
        "lsUbid":f"X{ubid_main}:{now_ms//1000}",
        "referrer":"https://view.awsapps.com/",
        "userAgent":UA["user-agent"],
        "location":location_url,
        "webDriver":False,
        "capabilities":{"css":{"textShadow":1,"WebkitTextStroke":1,
            "boxShadow":1,"borderRadius":1,"borderImage":1,"opacity":1,
            "transform":1,"transition":1},
            "js":{"audio":True,"geolocation":True,
            "localStorage":"supported","touch":False,"video":True,
            "webWorker":True},"elapsed":0},
        "gpu":{"vendor":"Google Inc. (Apple)",
            "model":"ANGLE (Apple, ANGLE Metal Renderer: Apple M4, "
                    "Unspecified Version)",
            "extensions":GPU_EXT},
        "dnt":None,
        "math":{"tan":"-1.4214488238747245",
            "sin":"0.8178819121159085","cos":"-0.5753861119575491"},
        "form":{},
        "canvas":{"hash":canvas_hash,"emailHash":None,
            "histogramBins":REAL_HIST},
        "token":{"isCompatible":False,"pageHasCaptcha":0},
        "auth":{"form":{"method":"get"}},
        "errors":[],"version":"4.0.0"}
    js=json.dumps(data,separators=(",",":"),ensure_ascii=False)
    crc=format(binascii.crc32(js.encode())&0xFFFFFFFF,"08X")
    plain=crc+"#"+js
    enc=_xxtea_enc(plain,XXTEA_KEY)
    b64=base64.b64encode(enc).decode().rstrip("=")
    return "ECdITeCs:"+b64

# ═══ JWE 密码加密 ═══
def encrypt_password_jwe(password, public_key_jwk):
    """★ v10修复: 浏览器加密的不是裸密码, 而是包含 JWT claims 的 JSON payload.
    app.js PasswordEncryptor.encryptPassword 的逻辑:
    g = {iss, iat, nbf, jti, exp, aud, password}
    encrypt(JSON.stringify(g))"""
    key = jwk.JWK(**public_key_jwk)
    protected = json.dumps({
        "alg": "RSA-OAEP-256",
        "kid": public_key_jwk["kid"],
        "enc": "A256GCM",
        "cty": "enc",
        "typ": "application/aws+signin+jwe"
    }, separators=(",", ":"))
    # ★ 构造 JWT-like payload (和浏览器 app.js 一致)
    now = int(time.time())
    plaintext = json.dumps({
        "iss": "us-east-1.signin",
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "exp": now + 300,  # PASSWORD_PERIOD = 300
        "aud": "us-east-1.AWSPasswordService",
        "password": password
    }, separators=(",", ":"))
    token = jwe.JWE(plaintext.encode("utf-8"),
                    recipient=key,
                    protected=protected)
    return token.serialize(compact=True)

# ═══ 辅助函数 ═══
def _pkce():
    v=secrets.token_urlsafe(43)
    c=base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()
        ).rstrip(b"=").decode()
    return v,c
def _vid():
    t=int(time.time()*1000)
    r="".join(random.choices(string.ascii_lowercase+string.digits,k=12))
    return f"{t}-{r}"
def _pwd(): return secrets.token_urlsafe(12)+"!A1"
def _uuid(): return str(uuid.uuid4())
def _ubid():
    return f"{random.randint(100,999)}-{random.randint(1000000,9999999)}-{random.randint(1000000,9999999)}"

class KiroRegister:
    def __init__(self,proxy=None,tag="REG"):
        self.tag=tag; self.proxy=proxy
        self.s=curl_requests.Session(impersonate="chrome146")
        if proxy: self.s.proxies={"https":proxy,"http":proxy}
        self.cv,self.cc=_pkce()
        self.state=_uuid(); self.vid=_vid()
        self.wsh=None; self.sid=None
        self.profile_wf_id=None; self.profile_wf_state=None
        self._awsd2c_token=None; self._tes_visitor_id=None
        self._profile_ubid=_ubid(); self._profile_load_ts=None
        self._aws_ubid_main=None
        self._canvas_hash=random.randint(1000000000,2147483647)
        self._login_wsh=None
        self._signup_wsh=None
        # ★ v10: 只有 platform-ubid 是 JS 生成的
        self._platform_ubid=_ubid()
        # ★ Step 12 token flow 需要的数据
        self._portal_csrf_token=None   # portal.sso/login 返回的 csrfToken
        self._orchestrator_id=None     # step 2 redirect chain 中的 orchestrator_id
        self._callback_url=None        # step 2 redirect chain 中的 callback_url
        self._initiate_redirect_url=None
        self._app_oauth_code=None
        self._app_oauth_state=None
        self._workflow_result_handle=None  # step 10 redirect URL 中的 workflowResultHandle
        self._step10_workflow_result_handle=None
        self._step10_state=None
        self._step11_state=None        # step 11 redirect URL 中的 state
        self._step11_workflow_result_handle=None

    def log(self,msg): print(f"[{self.tag}] {msg}")

    @staticmethod
    def _pick_query_value(*mappings, keys):
        for mapping in mappings:
            if not mapping:
                continue
            for key in keys:
                value = mapping.get(key)
                if isinstance(value, list):
                    if value and value[0]:
                        return value[0]
                elif value:
                    return value
        return None

    def _extract_auth_context_from_url(self, url, source="url", depth=0):
        if not url:
            return {"orchestrator_id": None, "callback_url": None, "workflow_state_handle": None}
        try:
            p = urlparse(str(url))
            qs = parse_qs(p.query)
            fqs = parse_qs(p.fragment.lstrip("#/?")) if p.fragment else {}
        except Exception as e:
            self.log(f"  [debug] parse {source} failed: {e}")
            return {"orchestrator_id": None, "callback_url": None, "workflow_state_handle": None}

        oid = self._pick_query_value(qs, fqs, keys=("orchestrator_id", "orchestration_id", "orchestrationId"))
        cb = self._pick_query_value(qs, fqs, keys=("callback_url",))
        wsh = self._pick_query_value(qs, fqs, keys=("workflowStateHandle",))
        req_uri = self._pick_query_value(qs, fqs, keys=("request_uri",))
        oauth_code = self._pick_query_value(qs, fqs, keys=("code",))
        oauth_state = self._pick_query_value(qs, fqs, keys=("state",))

        if oid and oid != self._orchestrator_id:
            self._orchestrator_id = oid
            self.log(f"  [debug] {source} captured orchestrator_id={oid[:60]}...")
        if cb and cb != self._callback_url:
            self._callback_url = cb
            self.log(f"  [debug] {source} captured callback_url={cb}")
        if wsh and not self.wsh:
            self.wsh = wsh
            self._login_wsh = wsh
            self.log(f"  [debug] {source} captured workflowStateHandle={wsh}")
        if req_uri:
            self.log(f"  [debug] {source} contains request_uri={req_uri[:80]}...")
        if p.netloc == "app.kiro.dev" and p.path == "/signin/oauth" and oauth_code:
            self._app_oauth_code = oauth_code
            if oauth_state:
                self._app_oauth_state = oauth_state
            self.log(f"  [debug] {source} captured app oauth code={oauth_code[:40]}...")

        nested_context = {"orchestrator_id": None, "callback_url": None, "workflow_state_handle": None}
        if depth < 2:
            nested_keys = (
                "redirect_url",
                "redirectUrl",
                "return_url",
                "returnUrl",
                "resume_url",
                "resumeUrl",
            )
            for key in nested_keys:
                nested_value = self._pick_query_value(qs, fqs, keys=(key,))
                if not nested_value:
                    continue
                nested_text = str(nested_value).strip()
                if "://" not in nested_text:
                    continue
                nested_context = self._extract_auth_context_from_url(
                    nested_text,
                    f"{source} nested {key}",
                    depth=depth + 1,
                )
                if nested_context.get("orchestrator_id") or nested_context.get("workflow_state_handle"):
                    break

        return {
            "orchestrator_id": oid or nested_context.get("orchestrator_id"),
            "callback_url": cb or nested_context.get("callback_url"),
            "workflow_state_handle": wsh or nested_context.get("workflow_state_handle"),
        }

    def _scan_redirect_chain(self, response, source="redirect chain"):
        chain = list(getattr(response, "history", []) or [])
        if not chain:
            return
        for idx, resp in enumerate(chain, start=1):
            try:
                url = str(resp.url)
            except Exception:
                url = ""
            if url:
                self.log(f"  [debug] {source} #{idx} url={url[:180]}")
                self._extract_auth_context_from_url(url, f"{source} #{idx} url")
            try:
                location = resp.headers.get("location") or resp.headers.get("Location")
            except Exception:
                location = None
            if location:
                self.log(f"  [debug] {source} #{idx} location={location[:180]}")
                self._extract_auth_context_from_url(location, f"{source} #{idx} location")

    @staticmethod
    def _get_kiro_stage():
        hostname = (urlparse(KIRO).hostname or "").lower()
        if hostname.startswith("beta."):
            return "beta"
        if hostname.startswith("gamma."):
            return "gamma"
        return "prod"

    @classmethod
    def _get_official_profile_arn(cls, idp="BuilderId"):
        stage = cls._get_kiro_stage()
        family = "social" if idp in {"Google", "Github"} else "builder_id"
        return OFFICIAL_STAGE_PROFILE_ARNS.get(family, {}).get(stage)

    def _normalize_exchange_token_response(self, resp_data, *, session_token=None, source="ExchangeToken"):
        access_token = resp_data.get("accessToken", "")
        kiro_csrf = resp_data.get("csrfToken", "")
        profile_arn = resp_data.get("profileArn", "")
        expires_in = resp_data.get("expiresIn", 0)

        if not access_token:
            self.log(f"  ❌ {source} missing accessToken: {resp_data}")
            return None

        self.log(f"  ✅ accessToken={access_token[:60]}...")
        self.log(f"  ✅ csrfToken={kiro_csrf[:30]}...")
        if profile_arn:
            self.log(f"  ✅ profileArn={profile_arn}")
        else:
            self.log(f"  ⚠️ {source} missing profileArn; continuing without it")
        self.log(f"  expiresIn={expires_in}")
        return {
            "accessToken": access_token,
            "sessionToken": session_token,
            "csrfToken": kiro_csrf,
            "profileArn": profile_arn or None,
            "expiresIn": expires_in,
        }

    def _kiro_rpc_headers(self, *, access_token=None, csrf_token=None):
        headers = {
            **UA,
            "accept": "application/cbor",
            "content-type": "application/cbor",
            "smithy-protocol": "rpc-v2-cbor",
            "origin": KIRO,
            "referer": f"{KIRO}/signin",
            "x-kiro-visitorid": self.vid,
            "amz-sdk-invocation-id": _uuid(),
            "amz-sdk-request": "attempt=1; max=1",
            "x-amz-user-agent": X_AMZ_UA,
        }
        if access_token:
            headers["authorization"] = f"Bearer {access_token}"
        if csrf_token:
            headers["x-csrf-token"] = csrf_token
        return headers

    def _upgrade_kiro_chat_token(self, token_info, *, source):
        if not token_info:
            return None

        access_token = token_info.get("accessToken") or ""
        csrf_token = token_info.get("csrfToken") or ""
        profile_arn = token_info.get("profileArn") or ""
        session_token = token_info.get("sessionToken")
        expires_in = token_info.get("expiresIn", 0)
        cookies = {"kiro-visitor-id": self.vid}
        empty_cbor_map = cbor2.dumps({})

        def _merge_normalized(resp_data, *, resp_source, default_csrf=None):
            merged = dict(resp_data or {})
            if profile_arn and not merged.get("profileArn"):
                merged["profileArn"] = profile_arn
            if default_csrf and not merged.get("csrfToken"):
                merged["csrfToken"] = default_csrf
            if not merged.get("expiresIn") and expires_in:
                merged["expiresIn"] = expires_in
            normalized = self._normalize_exchange_token_response(
                merged,
                session_token=session_token,
                source=resp_source,
            )
            if normalized:
                self.log(f"  ✅ {resp_source} upgraded bearer token")
                return normalized
            return None

        if access_token and csrf_token:
            self.log(f"  12z: POST RefreshToken ({source})...")
            refresh_headers = self._kiro_rpc_headers(
                access_token=access_token,
                csrf_token=csrf_token,
            )
            r = self.s.post(
                f"{KIRO}/service/KiroWebPortalService/operation/RefreshToken",
                headers=refresh_headers,
                data=empty_cbor_map,
                cookies=cookies,
            )
            self.log(f"  RefreshToken status: {r.status_code}")
            if r.status_code == 200:
                try:
                    resp_data = cbor2.loads(r.content)
                except Exception as e:
                    self.log(f"  ❌ RefreshToken CBOR failed: {e}")
                else:
                    upgraded = _merge_normalized(
                        resp_data,
                        resp_source=f"{source} RefreshToken",
                    )
                    if upgraded:
                        return upgraded
            else:
                try:
                    self.log(f"  ⚠️ RefreshToken failed: {r.text[:300]}")
                except Exception:
                    self.log(f"  ⚠️ RefreshToken failed with binary response len={len(r.content)}")

        if access_token and csrf_token:
            self.log(f"  12z2: POST GetToken ({source})...")
            get_token_headers = self._kiro_rpc_headers(
                access_token=access_token,
                csrf_token=csrf_token,
            )
            r = self.s.post(
                f"{KIRO}/service/KiroWebPortalService/operation/GetToken",
                headers=get_token_headers,
                data=empty_cbor_map,
                cookies=cookies,
            )
            self.log(f"  GetToken status: {r.status_code}")
            if r.status_code == 200:
                try:
                    resp_data = cbor2.loads(r.content)
                except Exception as e:
                    self.log(f"  ❌ GetToken CBOR failed: {e}")
                else:
                    upgraded = _merge_normalized(
                        resp_data,
                        resp_source=f"{source} GetToken",
                        default_csrf=csrf_token,
                    )
                    if upgraded:
                        return upgraded
            else:
                try:
                    self.log(f"  ⚠️ GetToken failed: {r.text[:300]}")
                except Exception:
                    self.log(f"  ⚠️ GetToken failed with binary response len={len(r.content)}")

        return token_info

    def _refresh_oidc_context_after_login(self):
        self.log("  12x: retry InitiateLogin with logged-in SSO session...")
        try:
            redir = self.step1_kiro_init()
            if not redir:
                self.log("  ⚠️ retry InitiateLogin returned no redirectUrl")
                return False
            ok = self.step2_get_wsh(redir)
            if not ok:
                self.log("  ⚠️ retry redirect chain did not produce workflow context")
                return False
            if self._app_oauth_code:
                self.log(f"  ✅ recovered app oauth code={self._app_oauth_code[:40]}...")
                return True
            if self._orchestrator_id:
                self.log(f"  ✅ recovered orchestrator_id={self._orchestrator_id[:60]}...")
            else:
                self.log("  ⚠️ retry finished but orchestrator_id is still missing")
            return True
        except Exception as e:
            self.log(f"  ⚠️ retry OIDC context failed: {e}")
            return False

    def _exchange_app_oauth_code(self):
        if not self._app_oauth_code:
            self.log("  ❌ missing app oauth code")
            return None
        self.log("  12y: direct app.kiro.dev oauth callback -> ExchangeToken...")
        exchange_h = self._kiro_rpc_headers()
        redirect_state = self._app_oauth_state or self.state
        self.log(f"  code={self._app_oauth_code[:60]}...")
        self.log(f"  state={redirect_state[:60]}...")
        exchange_body = cbor2.dumps({
            "code": self._app_oauth_code,
            "codeVerifier": self.cv,
            "idp": "BuilderId",
            "redirectUri": f"{KIRO}/signin/oauth",
            "state": redirect_state,
        })
        r = self.s.post(
            f"{KIRO}/service/KiroWebPortalService/operation/ExchangeToken",
            headers=exchange_h,
            data=exchange_body,
            cookies={"kiro-visitor-id": self.vid},
        )
        self.log(f"  Status: {r.status_code}")
        if r.status_code != 200:
            self.log(f"  ❌ direct ExchangeToken failed: {r.status_code}")
            try:
                self.log(f"  {r.text[:500]}")
            except Exception:
                self.log(f"  (binary response, len={len(r.content)})")
            return None
        try:
            resp_data = cbor2.loads(r.content)
        except Exception as e:
            self.log(f"  ❌ direct ExchangeToken CBOR failed: {e}")
            return None
        normalized = self._normalize_exchange_token_response(
            resp_data,
            session_token=None,
            source="direct ExchangeToken",
        )
        upgraded = self._upgrade_kiro_chat_token(
            normalized,
            source="direct ExchangeToken",
        )
        if not upgraded:
            return None

        if not self._token_survives_chat_probe(
            upgraded,
            source="direct ExchangeToken",
        ):
            self.log(
                "  ⚠️ direct app oauth token failed chat probe, "
                "falling back to full SSO auth-code flow"
            )
            return None
        return upgraded

    def _token_survives_chat_probe(self, token_info, *, source):
        access_token = str((token_info or {}).get("accessToken") or "").strip()
        if not access_token:
            return False

        try:
            from ..credential.types import KiroCredentials
            from ..providers.kiro import KiroProvider

            creds = KiroCredentials.from_dict(
                {
                    "accessToken": access_token,
                    "profileArn": token_info.get("profileArn"),
                    "authMethod": "social",
                }
            )
            provider = KiroProvider(credentials=creds)
            headers = provider.build_headers(access_token)
            payload = provider.build_request(
                user_content="ping",
                model="claude-haiku-4.5",
                history=[],
            )
            response = self.s.post(
                "https://q.us-east-1.amazonaws.com/generateAssistantResponse",
                headers=headers,
                json=payload,
            )
        except Exception as e:
            self.log(f"  ⚠️ {source} chat probe skipped: {e}")
            return True

        self.log(f"  {source} chat probe status: {response.status_code}")
        if response.status_code == 200:
            return True
        if response.status_code not in (401, 403):
            return True

        try:
            body = response.text[:300]
        except Exception:
            body = f"(binary response len={len(response.content)})"
        self.log(f"  ⚠️ {source} chat probe rejected token: {body}")
        return False

    def _capture_cookies(self,resp):
        """捕获 Set-Cookie 响应头中的 cookies.
        ★ v10修复: 对有 Domain= 的 Set-Cookie, 同时存储到裸域名,
        避免 .domain 和裸域名各一份导致重复发送."""
        hostname = urlparse(str(resp.url)).hostname or "us-east-1.signin.aws"
        for k,v in resp.headers.multi_items():
            if k.lower()!="set-cookie": continue
            m=re.match(r"([^=]+)=([^;]*)",v)
            if not m: continue
            name,value=m.group(1),m.group(2)
            dm=re.search(r"[Dd]omain=([^;,\s]+)",v)
            pm=re.search(r"[Pp]ath=([^;,\s]+)",v)
            path=pm.group(1) if pm else "/"
            if name=="aws-ubid-main": self._aws_ubid_main=value
            if dm:
                # 有 Domain 属性: 浏览器会把它当作 domain cookie
                # 但 curl_cffi 可能同时发送 .domain 和裸域名的 cookie
                # 只存储到裸域名, 避免重复
                domain = dm.group(1).lstrip(".")
                # 先删掉可能存在的 .domain 版本
                dot_domain = "." + domain
                try: self.s.cookies.delete(name, domain=dot_domain, path=path)
                except: pass
                self.s.cookies.set(name,value,domain=domain,path=path)
            else:
                # 无 Domain 属性: host-only cookie
                self.s.cookies.set(name,value,domain=hostname,path=path)

    def _setup_signin_js_cookies(self, step_id=None):
        """★ v10重写: 只设置真正由浏览器 JS 生成的 cookies.
        HAR 分析证实: workflow-csrf-token, workflow-csrftoken, directory-csrf-token,
        login-interview-token, workflow-step-id 都是服务端 Set-Cookie 设置的.
        只有 platform-ubid 是 JS 生成的."""
        domain = "us-east-1.signin.aws"
        # platform-ubid: 唯一真正由 JS 生成的 cookie
        try: self.s.cookies.delete("platform-ubid", domain=domain, path="/platform")
        except: pass
        self.s.cookies.set("platform-ubid", self._platform_ubid,
                           domain=domain, path="/platform")

    def _update_directory_csrf_with_signup(self):
        """★ v10新增: Step 4a 后, 从服务端返回的 workflow-csrf-token 中
        提取 signupCsrfToken, 更新 directory-csrf-token."""
        from urllib.parse import unquote as url_unquote
        domain = "us-east-1.signin.aws"
        # ★ 收集所有版本, 优先取裸域名的 (有最新的 signupCsrfToken)
        wf_by_domain = {}
        dir_by_domain = {}
        dir_csrf_path = f"/platform/{DIR_ID}"
        for c in self.s.cookies.jar:
            if "signin.aws" not in (c.domain or ""): continue
            if c.name == "workflow-csrf-token":
                wf_by_domain[c.domain] = c.value
                self.log(f"  [debug] wf-csrf-token: domain={c.domain} val={c.value[:80]}")
            elif c.name == "directory-csrf-token":
                dir_by_domain[c.domain] = (c.value, c.path)
                self.log(f"  [debug] dir-csrf-token: domain={c.domain} path={c.path} val={c.value[:80]}")
        # 优先裸域名 (us-east-1.signin.aws), 其次 .域名
        wf_csrf_val = wf_by_domain.get(domain) or wf_by_domain.get(f".{domain}")
        dir_entry = dir_by_domain.get(domain) or dir_by_domain.get(f".{domain}")
        dir_csrf_val = dir_entry[0] if dir_entry else None
        if dir_entry:
            dir_csrf_path = dir_entry[1] or dir_csrf_path
        if not wf_csrf_val or not dir_csrf_val:
            self.log(f"  ⚠️ _update_directory_csrf: wf={wf_csrf_val is not None} dir={dir_csrf_val is not None}")
            return
        try:
            wf_decoded = json.loads(url_unquote(wf_csrf_val))
            dir_decoded = json.loads(url_unquote(dir_csrf_val))
            signup_token = wf_decoded.get("signupCsrfToken")
            self.log(f"  [debug] wf signupCsrfToken={signup_token}")
            self.log(f"  [debug] dir has signupCsrfToken? {'signupCsrfToken' in dir_decoded}")
            if signup_token and "signupCsrfToken" not in dir_decoded:
                dir_decoded["signupCsrfToken"] = signup_token
                new_val = url_quote(json.dumps(dir_decoded, separators=(",", ":")), safe="")
                # 删除所有 directory-csrf-token (裸域名和.域名)
                for c in list(self.s.cookies.jar):
                    if c.name == "directory-csrf-token":
                        try: self.s.cookies.delete(c.name, domain=c.domain, path=c.path)
                        except: pass
                self.s.cookies.set("directory-csrf-token", new_val,
                                   domain=domain, path=dir_csrf_path)
                self.log(f"  ★ directory-csrf-token 已添加 signupCsrfToken={signup_token[:12]}")
            elif signup_token:
                self.log(f"  ★ directory-csrf-token 已有 signupCsrfToken, 跳过")
        except Exception as e:
            self.log(f"  ⚠️ 更新 directory-csrf-token 失败: {e}")

    def _gen_signin_fwcim(self):
        """生成 signin.aws 页面的真实 FWCIM fingerprint."""
        loc_url = f"{SIGNIN}/platform/{DIR_ID}/signup?workflowStateHandle={self.wsh or ''}"
        ubid = self._aws_ubid_main or self._platform_ubid
        return gen_fwcim(loc_url, ubid, self._canvas_hash)

    def _safe_cookie_list(self, domain_filter=None):
        """★ v10: 安全遍历 cookies, 避免 CookieConflict."""
        result = []
        for c in self.s.cookies.jar:
            if domain_filter and domain_filter not in (c.domain or ""):
                continue
            result.append((c.name, c.value, c.domain, c.path))
        return result

    def _exec(self,step_id,inputs=None,prefix="",action_id=None,
              extra_fields=None,expect_status=200):
        """调用 signin.aws execute API."""
        url=f"{SIGNIN}/platform/{DIR_ID}{prefix}/api/execute"
        body={"stepId":step_id,"workflowStateHandle":self.wsh or "",
              "inputs":inputs or[],"requestId":_uuid()}
        if action_id: body["actionId"]=action_id
        if extra_fields: body.update(extra_fields)
        # use richer header set (sec-fetch-* + cache-control + pragma + priority
        # already come from UA, but keep explicit referer)
        h={**UA,"accept":"application/json, text/plain, */*",
           "content-type":"application/json; charset=UTF-8",
           "origin":SIGNIN,"referer":f"{SIGNIN}/platform/{DIR_ID}/login",
           "x-amzn-requestid":body["requestId"],
           "x-amz-date":time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}
        self.log(f"  POST {url}")
        self.log(f"  stepId='{step_id}' actionId={action_id} wsh={str(self.wsh)[:40]}...")
        r=self.s.post(url,headers=h,json=body)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)
        if expect_status is not None and r.status_code != expect_status:
            self.log(f"  ❌ expected {expect_status} got {r.status_code}: {r.text[:500]}"); return None
        if r.status_code != 200:
            # caller asked for non-200 (probe); just return raw response body if json
            try: return r.json()
            except: return {}
        try: d=r.json()
        except: self.log(f"  ❌ 非JSON: {r.text[:300]}"); return None
        if d.get("workflowStateHandle"): self.wsh=d["workflowStateHandle"]
        if d.get("stepId") is not None: self.sid=d["stepId"]
        self.log(f"  → sid={self.sid} wsh={str(self.wsh)[:40]}...")
        self.log(f"  Resp: {json.dumps(d,ensure_ascii=False)[:400]}")
        return d

    def _setup_profile_cookies(self):
        self.s.cookies.set("i18next","en-US",
            domain="profile.aws.amazon.com",path="/")
        if self._aws_ubid_main:
            self.s.cookies.set("aws-ubid-main",self._aws_ubid_main,
                domain=".amazon.com",path="/")
        awsccc=json.dumps({"e":1,"p":1,"f":1,"a":1,"i":_uuid(),"v":"1"},
            separators=(",",":"))
        self.s.cookies.set("awsccc",base64.b64encode(awsccc.encode()).decode(),
            domain="profile.aws.amazon.com",path="/")
        self.s.cookies.set("aws-user-profile-ubid",self._profile_ubid,
            domain="profile.aws.amazon.com",path="/")

    def _browser_data(self,page_name=None,event_type="PageLoad"):
        elapsed=0
        if self._profile_load_ts:
            elapsed=int((time.time()-self._profile_load_ts)*1000)
        loc_url=f"{SIGNIN}/platform/{DIR_ID}/login?workflowStateHandle={self.wsh or ''}"
        ubid_main=self._aws_ubid_main or _ubid()
        fp=gen_fwcim(loc_url,ubid_main,self._canvas_hash)
        bd={"attributes":{
                "fingerprint":fp,
                "eventTimestamp":time.strftime("%Y-%m-%dT%H:%M:%S.000Z",time.gmtime()),
                "timeSpentOnPage":str(max(elapsed,random.randint(2000,5000))),
                "eventType":event_type,
                "ubid":self._profile_ubid,
            },"cookies":{}}
        if page_name: bd["attributes"]["pageName"]=page_name
        if self._tes_visitor_id:
            bd["attributes"]["visitorId"]=self._tes_visitor_id
        return bd

    def _profile_headers(self):
        return {**UA,"accept":"*/*",
            "content-type":"application/json;charset=UTF-8",
            "origin":PROFILE,"priority":"u=1, i",
            "referer":f"{PROFILE}/?workflowID={self.profile_wf_id or ''}",
            "sec-fetch-site":"same-origin","sec-fetch-mode":"cors",
            "sec-fetch-dest":"empty"}

    def _profile_post(self,endpoint,payload):
        url=f"{PROFILE}{endpoint}"
        h=self._profile_headers()
        self.log(f"  POST {url}")
        r=self.s.post(url,headers=h,json=payload)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)
        if r.status_code not in(200,201):
            self.log(f"  ❌ {r.status_code}: {r.text[:500]}"); return None
        try:
            d=r.json()
            self.log(f"  Resp: {json.dumps(d,ensure_ascii=False)[:400]}")
            return d
        except: return {}

    # ═══ Kiro OpenTelemetry beacons (matches real Chrome SDK) ═══
    def _kiro_otel_attr(self, key, val):
        if isinstance(val, bool):
            return {"key": key, "value": {"boolValue": val}}
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return {"key": key, "value": {"doubleValue": float(val)}}
        return {"key": key, "value": {"stringValue": str(val)}}

    def _kiro_otel_dp(self, attrs_dict, start_ns, end_ns, value=1):
        return {
            "attributes": [self._kiro_otel_attr(k, v)
                           for k, v in attrs_dict.items()],
            "startTimeUnixNano": str(start_ns),
            "timeUnixNano": str(end_ns),
            "asDouble": value,
        }

    def _send_kiro_telemetry(self, kind):
        """Fire-and-forget OpenTelemetry beacon to mimic Kiro web portal SDK.
        kind: 'page_view_signin' | 'signin_event' | 'page_view_dashboard'
        Logs but never raises (best-effort to add behavioral signal)."""
        try:
            end_ns = int(time.time() * 1e9)
            start_ns = end_ns - 1_000_000_000  # 1 sec window
            resource_attrs = [
                self._kiro_otel_attr("service.name", "kiro.web.portal"),
                self._kiro_otel_attr("telemetry.sdk.language", "webjs"),
                self._kiro_otel_attr("telemetry.sdk.name", "opentelemetry"),
                self._kiro_otel_attr("telemetry.sdk.version", "1.30.1"),
                self._kiro_otel_attr("service.version", "1.0.0"),
            ]
            metrics = []
            if kind == "page_view_signin":
                # environment.events + page.views (matches HAR entry [13])
                metrics.append({
                    "name": "environment.events", "description": "", "unit": "",
                    "sum": {"aggregationTemporality": 1, "isMonotonic": True,
                        "dataPoints": [
                            self._kiro_otel_dp({
                                "OTelLib": "kiro.web.portal",
                                "Feature": "environment",
                                "Activity": "browser",
                                "Entity": "chrome",
                            }, start_ns, end_ns),
                            self._kiro_otel_dp({
                                "OTelLib": "kiro.web.portal",
                                "Feature": "environment",
                                "Activity": "os",
                                "Entity": "Windows",
                            }, start_ns, end_ns),
                        ]}})
                metrics.append({
                    "name": "page.views", "description": "", "unit": "",
                    "sum": {"aggregationTemporality": 1, "isMonotonic": True,
                        "dataPoints": [self._kiro_otel_dp({
                            "OTelLib": "kiro.web.portal",
                            "KiroClientVersion": "1.0.0",
                            "Activity": "pageView",
                            "Feature": "signin",
                            "Path": "/signin",
                            "UserId": "",
                        }, start_ns, end_ns)]}})
            elif kind == "signin_event":
                metrics.append({
                    "name": "signin.events", "description": "", "unit": "",
                    "sum": {"aggregationTemporality": 1, "isMonotonic": True,
                        "dataPoints": [self._kiro_otel_dp({
                            "OTelLib": "kiro.web.portal",
                            "Feature": "signin",
                            "Activity": "signinClick",
                            "Entity": "BuilderId",
                        }, start_ns, end_ns)]}})
            elif kind == "page_view_dashboard":
                metrics.append({
                    "name": "page.views", "description": "", "unit": "",
                    "sum": {"aggregationTemporality": 1, "isMonotonic": True,
                        "dataPoints": [self._kiro_otel_dp({
                            "OTelLib": "kiro.web.portal",
                            "KiroClientVersion": "1.0.0",
                            "Activity": "pageView",
                            "Feature": "dashboard",
                            "Path": "/",
                            "UserId": "",
                        }, start_ns, end_ns)]}})
            body = {"resourceMetrics": [{
                "resource": {"attributes": resource_attrs,
                             "droppedAttributesCount": 0},
                "scopeMetrics": [{
                    "scope": {"name": "kiro.web.portal", "version": ""},
                    "metrics": metrics}]}]}
            h = {**UA, "accept": "*/*",
                 "content-type": "application/json",
                 "origin": KIRO, "referer": f"{KIRO}/",
                 "sec-fetch-site": "cross-site",
                 "x-kiro-machineid": self.vid}
            r = self.s.post(
                "https://prod.us-east-1.telemetry.kiro.aws.dev/v1/metrics",
                headers=h, json=body, timeout=10)
            self.log(f"  [otel:{kind}] status={r.status_code}")
        except Exception as ex:
            self.log(f"  [otel:{kind}] err: {ex}")

    # ═══ Step 1: Kiro InitiateLogin ═══
    def step1_kiro_init(self):
        self.log("Step 1: Kiro InitiateLogin...")
        # Mimic real Chrome: page-view beacon fires BEFORE OAuth click
        self._send_kiro_telemetry("page_view_signin")
        time.sleep(random.uniform(0.3, 1.0))
        self._send_kiro_telemetry("signin_event")
        body=cbor2.dumps({"idp":"BuilderId",
            "redirectUri":f"{KIRO}/signin/oauth","state":self.state,
            "codeChallenge":self.cc,"codeChallengeMethod":"S256"})
        h={**UA,"accept":"application/cbor","content-type":"application/cbor",
           "smithy-protocol":"rpc-v2-cbor","origin":KIRO,
           "referer":f"{KIRO}/signin","x-kiro-visitorid":self.vid,
           "amz-sdk-invocation-id":_uuid(),"amz-sdk-request":"attempt=1; max=1",
           "x-amz-user-agent":X_AMZ_UA}
        r=self.s.post(f"{KIRO}/service/KiroWebPortalService/operation/InitiateLogin",
            headers=h,data=body,cookies={"kiro-visitor-id":self.vid})
        if r.status_code!=200: self.log(f"  ❌ {r.status_code}"); return None
        try: d=cbor2.loads(r.content)
        except: d=r.json()
        redir=d.get("redirectUrl")
        if not redir: self.log(f"  ❌ 无redirectUrl: {d}"); return None
        self._initiate_redirect_url = redir
        self._extract_auth_context_from_url(redir, "InitiateLogin redirectUrl")
        self.log(f"  ✅ {redir[:100]}...")
        return redir

    # ═══ Step 2: oidc → view → portal.sso → wsh ═══
    def step2_get_wsh(self,redir_url):
        self.log("Step 2: 重定向链...")
        self._extract_auth_context_from_url(redir_url, "step2 input redirect")
        current_url = redir_url
        final_response = None
        for hop in range(1, 12):
            r = self.s.get(current_url, headers=UA, allow_redirects=False)
            final_response = r
            self._capture_cookies(r)
            try:
                seen_url = str(r.url)
            except Exception:
                seen_url = current_url
            self.log(f"  [debug] step2 redirect chain #{hop} url={seen_url[:180]}")
            self._extract_auth_context_from_url(seen_url, f"step2 redirect chain #{hop} url")

            try:
                location = r.headers.get("location") or r.headers.get("Location")
            except Exception:
                location = None

            if not location or r.status_code not in (301, 302, 303, 307, 308):
                break

            next_url = urljoin(seen_url, location)
            self.log(f"  [debug] step2 redirect chain #{hop} location={next_url[:180]}")
            self._extract_auth_context_from_url(next_url, f"step2 redirect chain #{hop} location")
            current_url = next_url

        if final_response is None:
            self.log("  ❌ step2 redirect chain produced no response")
            return False

        view_url=str(final_response.url)
        self._extract_auth_context_from_url(view_url, "step2 final url")
        self.log(f"  2a view: {view_url[:120]}")
        p=urlparse(view_url); qs=parse_qs(p.query)
        fqs=parse_qs(p.fragment.lstrip("#/?")) if p.fragment else {}
        oid=self._pick_query_value(qs, fqs, keys=("orchestrator_id", "orchestration_id", "orchestrationId"))
        cb=self._pick_query_value(qs, fqs, keys=("callback_url",))
        direct_wsh=self._pick_query_value(qs, fqs, keys=("workflowStateHandle",))
        if oid:
            # ★ 保存 orchestrator_id 和 callback_url (Step 12 需要)
            self._orchestrator_id=oid
            self._callback_url=cb
            self.log(f"  ★ orchestrator_id={oid[:60]}...")
            self.log(f"  ★ callback_url={cb}")
            vr=(f"https://view.awsapps.com/start/#/"
                f"?callback_url={url_quote(cb or '')}&orchestrator_id={oid}")
        elif self._app_oauth_code:
            self.log("  ★ direct app oauth callback detected")
            return True
        elif direct_wsh:
            # 新链路：authorize 已经直接落到 login?workflowStateHandle=...
            self.wsh=direct_wsh
            self._login_wsh=self.wsh
            if not self._callback_url:
                self._callback_url=(parse_qs(urlparse(redir_url).query).get("callback_url",[None])[0])
            self.log(f"  ★ direct workflowStateHandle={self.wsh}")
            vr=view_url
        else:
            self.log("  ❌ 无 orchestrator_id / workflowStateHandle")
            return False
        pu=(f"https://portal.sso.us-east-1.amazonaws.com/login"
             f"?directory_id=view&redirect_url={url_quote(vr)}")
        self.log("  2b portal.sso (CORS mode)...")
        r2=self.s.get(pu,headers={**UA,"accept":"*/*",
            "origin":"https://view.awsapps.com",
            "referer":"https://view.awsapps.com/",
            "sec-fetch-site":"cross-site","sec-fetch-mode":"cors",
            "sec-fetch-dest":"empty"},allow_redirects=False)
        self.log(f"  Status: {r2.status_code}")
        try:
            d=r2.json(); redir=d.get("redirectUrl","")
            # ★ 保存 csrfToken (Step 12a 需要)
            csrf=d.get("csrfToken")
            if csrf:
                self._portal_csrf_token=str(csrf)
                self.log(f"  ★ portal csrfToken={self._portal_csrf_token}")
            m=re.search(r"workflowStateHandle=([^&#]+)",redir)
            if m:
                self.wsh=m.group(1); self.log(f"  ✅ wsh={self.wsh}")
                self._login_wsh=self.wsh
                r3=self.s.get(redir,headers={**UA,"accept":"text/html",
                    "referer":"https://portal.sso.us-east-1.amazonaws.com/"},
                    allow_redirects=True)
                self._capture_cookies(r3)
                # ★ v10: 首次加载 login 页面后只设置 JS 生成的 platform-ubid
                self._setup_signin_js_cookies()
                return True
            if direct_wsh and self._portal_csrf_token:
                self.log("  ✅ direct wsh + portal csrfToken")
                self._setup_signin_js_cookies()
                return True
        except Exception as e: self.log(f"  ❌ portal.sso: {e}")
        return False

    # ═══ Step 3: signin.aws → SIGNUP ═══
    def step3_signin_flow(self,email):
        self.log("Step 3: signin.aws workflow...")
        fp_i={"input_type":"FingerPrintRequestInput","fingerPrint":self._gen_signin_fwcim()}
        usr_i={"input_type":"UserRequestInput","username":email}
        self.log("  3a: init (stepId='')...")
        if not self._exec("",inputs=[fp_i]): return None
        self.log("  3b: start → get-identity-user...")
        if not self._exec("start",inputs=[fp_i]): return None
        # 3b': humanlike dwell on IDENTIFICATION page (real user typed for ~13s)
        identification_dwell_ms = random.randint(9000, 18000)
        time.sleep(identification_dwell_ms / 1000.0)
        # 3c-pre: SUBMIT first (real Chrome flow shows AWS verifying user doesn't exist).
        # Real HAR: POST get-identity-user actionId=SUBMIT with ApplicationTypeRequestInput +
        # UserEventRequestInput (PAGE_SUBMIT IDENTIFICATION timeSpentOnPage=~13s) → 400 expected.
        self.log("  3c-pre: SUBMIT (probe, expect 400)...")
        app_type_i = {"input_type":"ApplicationTypeRequestInput",
                      "applicationType":"SSO_INDIVIDUAL_ID"}
        evt_id_i = {"input_type":"UserEventRequestInput",
                    "directoryId":DIR_ID,
                    "userName":email,
                    "userEvents":[{"input_type":"UserEvent",
                                   "eventType":"PAGE_SUBMIT",
                                   "pageName":"IDENTIFICATION",
                                   "timeSpentOnPage":identification_dwell_ms}]}
        fp_i_submit = {"input_type":"FingerPrintRequestInput",
                       "fingerPrint":self._gen_signin_fwcim()}
        self._exec("get-identity-user",
                   inputs=[usr_i, app_type_i, evt_id_i, fp_i_submit],
                   action_id="SUBMIT",
                   expect_status=None)
        # short pause as a user clicking "Sign up instead" CTA
        time.sleep(random.uniform(0.4, 1.2))
        self.log("  3c: SIGNUP...")
        fp_i_signup = {"input_type":"FingerPrintRequestInput",
                       "fingerPrint":self._gen_signin_fwcim()}
        r=self._exec("get-identity-user",inputs=[usr_i,fp_i_signup],action_id="SIGNUP")
        if not r: return None
        redir=r.get("redirect",{}).get("url")
        if redir:
            self.log(f"  ✅ signup redirect: {redir[:100]}...")
            m=re.search(r"workflowStateHandle=([^&#]+)",redir)
            if m: self.wsh=m.group(1)
        return r

    # ═══ Step 4: signup → profile.aws redirect ═══
    def step4_signup_flow(self,email):
        self.log("Step 4: signup workflow...")
        fp_i={"input_type":"FingerPrintRequestInput","fingerPrint":self._gen_signin_fwcim()}
        usr_i={"input_type":"UserRequestInput","username":email}
        self.log("  4a: signup init...")
        if not self._exec("",inputs=[usr_i,fp_i],prefix="/signup"): return None
        # ★ v10: Step 4a 后, 服务端在 workflow-csrf-token 中添加了 signupCsrfToken
        # 需要同步到 directory-csrf-token (浏览器 JS 做的事)
        self._update_directory_csrf_with_signup()
        self.log("  4b: signup start...")
        r=self._exec("start",inputs=[usr_i,fp_i],prefix="/signup")
        if not r: return None
        redir=r.get("redirect",{}).get("url","")
        if "profile.aws" in redir:
            self.log(f"  ✅ profile redirect: {redir[:100]}...")
            m=re.search(r"workflowID=([^&#]+)",redir)
            if m:
                self.profile_wf_id=m.group(1)
                self.log(f"  workflowID: {self.profile_wf_id}")
        self._signup_wsh=self.wsh
        return r

    # ═══ Step 5: TES token ═══
    def step5_get_tes_token(self):
        self.log("Step 5: 获取 TES token...")
        self.log("  加载 signin.aws 资源...")
        for path in["/assets/js/app.js"]:
            r=self.s.get(f"{SIGNIN}{path}",headers={**UA,"accept":"*/*",
                "referer":f"{SIGNIN}/platform/{DIR_ID}/login"})
            self._capture_cookies(r)
        self.s.post(f"{SIGNIN}/metrics/fingerprint",
            headers={**UA,"accept":"*/*","content-type":"application/json",
                "origin":SIGNIN,"referer":f"{SIGNIN}/platform/{DIR_ID}/login"},
            json={"fingerprint":self._gen_signin_fwcim()})
        r=self.s.post("https://vs.aws.amazon.com/token",
            headers={**UA,"accept":"*/*","content-type":"application/json",
                "origin":SIGNIN,"referer":f"{SIGNIN}/",
                "sec-fetch-site":"cross-site","sec-fetch-mode":"cors",
                "sec-fetch-dest":"empty"},json={})
        self._capture_cookies(r)
        self.log(f"  Status: {r.status_code}")
        if r.status_code==200:
            d=r.json(); token=d.get("token","")
            self.log(f"  ✅ awsd2c-token: {token[:60]}...")
            self._awsd2c_token=token
            try:
                parts=token.split(".")
                pb=parts[1]+"="*(4-len(parts[1])%4)
                jp=json.loads(base64.urlsafe_b64decode(pb))
                self._tes_visitor_id=jp.get("vid")
                self.log(f"  ✅ visitorId: {self._tes_visitor_id}")
            except: pass
            self.s.cookies.set("awsd2c-token",token,
                domain=".aws.amazon.com",path="/")
            self.s.cookies.set("awsd2c-token-c",token,
                domain=".aws.amazon.com",path="/")
            # ★ v8: 也设置到 signin.aws 域
            self.s.cookies.set("awsd2c-token-c",token,
                domain="us-east-1.signin.aws",path="/")
            return token
        self.log(f"  ❌ {r.status_code}: {r.text[:300]}"); return None

    # ═══ Step 6: profile.aws 页面加载 + /api/start ═══
    def step6_profile_load(self):
        self.log("Step 6: profile.aws 页面加载...")
        if not self.profile_wf_id:
            self.log("  ❌ 无workflowID"); return None
        self._setup_profile_cookies()
        self.log("  6a: GET profile 页面...")
        r=self.s.get(f"{PROFILE}?workflowID={self.profile_wf_id}",
            headers={**UA,"accept":"text/html","referer":f"{SIGNIN}/"},
            allow_redirects=True)
        self._capture_cookies(r)
        self._profile_load_ts=time.time()
        self.log(f"  页面 status: {r.status_code}")
        for res in["/dist/main/app_3d2790dc68bef818e50a.min.js",
                   "/dist/main/app_f95ebcaf22d26fd182da.min.css"]:
            self.s.get(f"{PROFILE}{res}",headers={**UA,"accept":"*/*",
                "referer":f"{PROFILE}/?workflowID={self.profile_wf_id}"})
        time.sleep(0.3)
        self.log("  6b: POST /api/get-config...")
        self._profile_post("/api/get-config",{})
        self.log("  6c: POST /api/get-app-context...")
        self.s.post(f"{PROFILE}/api/get-app-context",
            headers=self._profile_headers(),
            json={"workflowID":self.profile_wf_id})
        time.sleep(0.5)
        self.log("  6d: POST /api/start...")
        payload={"workflowID":self.profile_wf_id,
                 "browserData":self._browser_data()}
        r=self._profile_post("/api/start",payload)
        if r and r.get("workflowState"):
            self.profile_wf_state=r["workflowState"]
            self.log(f"  ✅ workflowState: {self.profile_wf_state}")
        return r

    # ═══ Step 7: send-otp ═══
    def step7_send_otp(self,email):
        self.log(f"Step 7: send-otp to {email}...")
        time.sleep(random.uniform(2.0,4.0))
        payload={"workflowState":self.profile_wf_state,"email":email,
            "browserData":self._browser_data(page_name="EMAIL_COLLECTION",
                event_type="PageSubmit")}
        return self._profile_post("/api/send-otp",payload)

    # ═══ Step 8: create-identity (OTP验证 + 创建身份) ═══
    def step8_create_identity(self, otp, email, full_name):
        self.log("Step 8: create-identity...")
        time.sleep(random.uniform(1.0, 3.0))
        payload = {
            "workflowState": self.profile_wf_state,
            "userData": {"email": email, "fullName": full_name},
            "otpCode": otp,
            "browserData": self._browser_data(
                page_name="EMAIL_VERIFICATION",
                event_type="EmailVerification")
        }
        r = self._profile_post("/api/create-identity", payload)
        if not r: return None
        reg_code = r.get("registrationCode")
        sign_in_state = r.get("signInState")
        if not reg_code or not sign_in_state:
            self.log(f"  ❌ 缺少 registrationCode 或 signInState")
            return None
        self.log(f"  ✅ registrationCode: {reg_code[:40]}...")
        try:
            padded = sign_in_state + "=" * (4 - len(sign_in_state) % 4)
            decoded = json.loads(base64.b64decode(padded))
            self.log(f"  signInState decoded: {decoded}")
        except: pass
        return r

    # ═══ Step 9: signup execute (registrationCode → get-new-password) ═══
    def step9_signup_registration(self, reg_code, sign_in_state):
        self.log("Step 9: signup with registrationCode...")

        # ★ v10: 只设置 JS 生成的 cookies (platform-ubid)
        self._setup_signin_js_cookies()
        # 确保 awsccc cookie 在 signin.aws 域 (先删旧的避免冲突)
        try: self.s.cookies.delete("awsccc", domain="us-east-1.signin.aws")
        except: pass
        awsccc = json.dumps({"e":1,"p":1,"f":1,"a":1,"i":_uuid(),"v":"1"},
                            separators=(",",":"))
        self.s.cookies.set("awsccc",
                           base64.b64encode(awsccc.encode()).decode(),
                           domain="us-east-1.signin.aws", path="/")

        # 9a: GET signup 页面 (HAR entry 125)
        signup_url = (f"{SIGNIN}/platform/{DIR_ID}/signup"
                      f"?registrationCode={reg_code}"
                      f"&state={sign_in_state}")
        self.log(f"  9a: GET {signup_url[:100]}...")
        r = self.s.get(signup_url, headers={**UA, "accept": "text/html",
            "referer": f"{PROFILE}/"}, allow_redirects=True)
        self._capture_cookies(r)
        self.log(f"  Status: {r.status_code}")

        # 加载 app.js 和 config (模拟浏览器行为, HAR entries 116-123)
        self.s.get(f"{SIGNIN}/assets/js/app.js",
                   headers={**UA, "accept": "*/*", "referer": signup_url})
        self.s.get(f"{SIGNIN}/assets/css/app.css",
                   headers={**UA, "accept": "text/css", "referer": signup_url})
        self.s.get(f"{SIGNIN}/platform/config?directoryId=",
                   headers={**UA, "accept": "*/*", "referer": signup_url})

        time.sleep(0.5)

        # 9b: POST signup/api/execute
        req_id = _uuid()
        fwcim = self._gen_signin_fwcim()
        fp_i = {"input_type": "FingerPrintRequestInput", "fingerPrint": fwcim}
        reg_i = {
            "input_type": "UserRegistrationRequestInput",
            "registrationCode": reg_code,
            "state": sign_in_state
        }
        self.log("  9b: POST signup/api/execute (registrationCode)...")
        url = f"{SIGNIN}/platform/{DIR_ID}/signup/api/execute"
        body = {
            "stepId": "",
            "state": sign_in_state,
            "inputs": [reg_i, fp_i],
            "requestId": req_id
        }
        h = {**UA, "accept": "application/json, text/plain, */*",
             "content-type": "application/json; charset=UTF-8",
             "origin": SIGNIN,
             "x-amzn-requestid": req_id,
             "x-amz-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
             "referer": signup_url,
             "sec-fetch-site": "same-origin",
             "sec-fetch-mode": "cors",
             "sec-fetch-dest": "empty",
             "sec-gpc": "1",
             "priority": "u=1, i"}

        # ★ v8 debug: 打印发送的 cookies (用 _safe_cookie_list 避免冲突)
        self.log("  发送的 cookies (signin.aws):")
        for name,val,dom,path in self._safe_cookie_list("signin.aws"):
            self.log(f"    {name}={str(val)[:60]}... (domain={dom}, path={path})")

        self.log(f"  POST {url}")
        r = self.s.post(url, headers=h, json=body)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)

        if r.status_code != 200:
            self.log(f"  ❌ {r.status_code}: {r.text[:500]}")
            return None
        d = r.json()
        self.log(f"  → sid={d.get('stepId')} wsh={d.get('workflowStateHandle','')[:40]}")
        self.log(f"  Resp: {json.dumps(d,ensure_ascii=False)[:400]}")
        if d.get("stepId") != "get-new-password-for-password-creation":
            self.log(f"  ❌ 预期 get-new-password, 实际 {d.get('stepId')}")
            return None
        self.log("  ✅ 进入密码设置步骤")
        self._signup_reg_url = signup_url
        return d

    # ═══ Step 10: 设置密码 (JWE加密) ═══
    def step10_set_password(self, pwd, email, step9_resp):
        self.log("Step 10: 设置密码 (JWE加密)...")
        wsh = step9_resp.get("workflowStateHandle", "")
        enc_ctx = (step9_resp.get("workflowResponseData", {})
                   .get("encryptionContextResponse", {}))
        pub_key = enc_ctx.get("publicKey")
        if not pub_key:
            self.log("  ❌ 无公钥, 无法加密密码")
            return None
        self.log(f"  公钥 kid: {pub_key.get('kid')}")

        # ★ v10: 不再调用 _setup_signin_js_cookies — 让服务端 Set-Cookie 管理
        # 不再手动操作 aws-usi-authn 路径 — _capture_cookies 已正确处理

        # ★ v10: 清理 .domain 重复 cookies (curl_cffi 内部可能仍会产生)
        for c in list(self.s.cookies.jar):
            if c.domain and c.domain.startswith(".") and "signin.aws" in c.domain:
                try: self.s.cookies.delete(c.name, domain=c.domain, path=c.path)
                except: pass

        # ★ v8: 先发 send-event (HAR entry 96: PAGE_LOAD for CREDENTIAL_COLLECTION)
        fwcim = self._gen_signin_fwcim()
        fp_i = {"input_type": "FingerPrintRequestInput", "fingerPrint": fwcim}
        evt_load = {
            "inputs": [
                {"input_type": "UserEventRequestInput",
                 "directoryId": DIR_ID,
                 "userName": email,
                 "userEvents": [{"input_type": "UserEvent",
                                 "eventType": "PAGE_LOAD",
                                 "pageName": "CREDENTIAL_COLLECTION"}]},
                fp_i
            ],
            "requestId": _uuid()
        }
        referer = getattr(self, '_signup_reg_url', f"{SIGNIN}/platform/{DIR_ID}/signup")
        se_h = {**UA, "accept": "application/json, text/plain, */*",
                "content-type": "application/json; charset=UTF-8",
                "origin": SIGNIN,
                "x-amzn-requestid": evt_load["requestId"],
                "x-amz-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
                "referer": referer,
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty"}
        self.log("  10a: send-event (PAGE_LOAD CREDENTIAL_COLLECTION)...")
        self.s.post(f"{SIGNIN}/platform/user-event/send-event",
                    headers=se_h, json=evt_load)

        # ★ v8: 发 metrics/fingerprint (HAR entry 81)
        fwcim2 = self._gen_signin_fwcim()
        self.s.post(f"{SIGNIN}/metrics/fingerprint",
                    headers={**UA, "accept": "*/*",
                             "content-type": "application/x-www-form-urlencoded",
                             "origin": SIGNIN, "referer": referer},
                    data=f"name=IsFingerprintGenerated:Success&value={fwcim2}")

        time.sleep(random.uniform(1.0, 3.0))

        # 10b: JWE 加密密码并提交
        jwe_password = encrypt_password_jwe(pwd, pub_key)
        self.log(f"  ✅ JWE 加密完成, 长度={len(jwe_password)}")
        req_id = _uuid()
        fwcim3 = self._gen_signin_fwcim()
        fp_i2 = {"input_type": "FingerPrintRequestInput", "fingerPrint": fwcim3}
        pwd_i = {
            "input_type": "PasswordRequestInput",
            "password": jwe_password,
            "successfullyEncrypted": "SUCCESSFUL",
            "errorLog": None
        }
        usr_i = {"input_type": "UserRequestInput", "username": email}
        evt_i = {
            "input_type": "UserEventRequestInput",
            "directoryId": DIR_ID,
            "userName": email,
            "userEvents": [{
                "input_type": "UserEvent",
                "eventType": "PAGE_SUBMIT",
                "pageName": "CREDENTIAL_COLLECTION",
                "timeSpentOnPage": random.randint(8000, 25000)
            }]
        }
        url = f"{SIGNIN}/platform/{DIR_ID}/signup/api/execute"
        body = {
            "stepId": "get-new-password-for-password-creation",
            "workflowStateHandle": wsh,
            "actionId": "SUBMIT",
            "inputs": [pwd_i, evt_i, usr_i, fp_i2],
            "visitorId": self._tes_visitor_id or "",
            "requestId": req_id
        }
        h = {**UA, "accept": "application/json, text/plain, */*",
             "content-type": "application/json; charset=UTF-8",
             "origin": SIGNIN,
             "x-amzn-requestid": req_id,
             "x-amz-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
             "referer": referer,
             "sec-fetch-site": "same-origin",
             "sec-fetch-mode": "cors",
             "sec-fetch-dest": "empty",
             "sec-gpc": "1",
             "priority": "u=1, i"}

        # ★ v10核心: 清理所有非裸域名的 signin.aws cookies
        # curl_cffi 内部 redirect 处理会创建 .us-east-1.signin.aws cookies
        # 这些不走 _capture_cookies, 所以绕过了我们的修复
        # 浏览器只发送裸域名 (host-only) 的 cookies, 需要删除所有 .domain 版本
        cleanup_domains = [".us-east-1.signin.aws", ".signin.aws", "signin.aws"]
        cleaned = 0
        for c in list(self.s.cookies.jar):
            if c.domain in cleanup_domains:
                try:
                    self.s.cookies.delete(c.name, domain=c.domain, path=c.path)
                    cleaned += 1
                except: pass
        if cleaned:
            self.log(f"  ★ 已清理 {cleaned} 个非裸域名 cookies")

        # ★ v10 debug: 打印最终 cookies (关键 cookie 打印完整值)
        self.log("  10b cookies:")
        for name,val,dom,path in self._safe_cookie_list("signin.aws"):
            if name in ('directory-csrf-token', 'workflow-csrf-token', 'workflow-csrftoken', 'workflow-step-id'):
                from urllib.parse import unquote as _uq
                self.log(f"    {name}={_uq(str(val))} (d={dom} p={path})")
            else:
                self.log(f"    {name}={str(val)[:50]}... (d={dom} p={path})")

        self.log(f"  10b: POST {url}")
        r = self.s.post(url, headers=h, json=body)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)
        if r.status_code != 200:
            self.log(f"  ❌ {r.status_code}: {r.text[:500]}")
            return None
        d = r.json()
        self.log(f"  → sid={d.get('stepId')}")
        self.log(f"  Resp: {json.dumps(d,ensure_ascii=False)[:400]}")
        if d.get("stepId") != "end-of-user-registration-success":
            self.log(f"  ❌ 预期 end-of-user-registration-success")
            return None
        # ★ 保存 workflowResultHandle (Step 12a 需要作为 authCode)
        redir_url = d.get("redirect", {}).get("url", "")
        if redir_url:
            qs_redir = parse_qs(urlparse(redir_url).query)
            m_wrh = re.search(r"workflowResultHandle=([^&#]+)", redir_url)
            if m_wrh:
                self._workflow_result_handle = m_wrh.group(1)
                self._step10_workflow_result_handle = self._workflow_result_handle
                self.log(f"  ★ workflowResultHandle={self._workflow_result_handle}")
            state10 = qs_redir.get("state", [None])[0]
            if state10:
                self._step10_state = state10
                self.log(f"  ★ step10 state={state10[:60]}...")
        self.log("  ✅ 密码设置成功, 注册完成!")
        return d

    # ═══ Step 11: 最终登录 ═══
    def step11_final_login(self, email, step10_resp):
        self.log("Step 11: 最终登录...")
        redir = step10_resp.get("redirect", {}).get("url", "")
        if not redir:
            self.log("  ❌ 无 redirect URL")
            return None
        self.log(f"  redirect: {redir[:120]}...")
        p = urlparse(redir)
        qs = parse_qs(p.query)
        login_wsh = qs.get("workflowStateHandle", [None])[0]
        state = qs.get("state", [None])[0]
        wf_result = qs.get("workflowResultHandle", [None])[0]
        if not login_wsh or not state or not wf_result:
            self.log(f"  ❌ redirect 参数不完整")
            return None
        fwcim = self._gen_signin_fwcim()
        fp_i = {"input_type": "FingerPrintRequestInput", "fingerPrint": fwcim}
        usr_i = {"input_type": "UserRequestInput", "username": email}
        url = f"{SIGNIN}/platform/{DIR_ID}/api/execute"
        body = {
            "stepId": "",
            "workflowStateHandle": login_wsh,
            "workflowResultHandle": wf_result,
            "state": state,
            "inputs": [usr_i, fp_i],
            "visitorId": self._tes_visitor_id or "",
            "requestId": _uuid()
        }
        h = {**UA, "accept": "application/json",
             "content-type": "application/json",
             "origin": SIGNIN,
             "referer": f"{SIGNIN}/platform/{DIR_ID}/login"}
        self.log(f"  POST {url}")
        r = self.s.post(url, headers=h, json=body)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)
        if r.status_code != 200:
            self.log(f"  ❌ {r.status_code}: {r.text[:500]}")
            return None
        d = r.json()
        self.log(f"  → sid={d.get('stepId')}")
        if d.get("stepId") == "end-of-workflow-success":
            self.log("  ✅ 登录成功! workflow 完成!")
            # ★ 保存 redirect URL 中的 state 和 workflowResultHandle (Step 12a 需要)
            redir11 = d.get("redirect", {}).get("url", "")
            if redir11:
                p11 = urlparse(redir11)
                qs11 = parse_qs(p11.query)
                s11 = qs11.get("state", [None])[0]
                if s11:
                    self._step11_state = s11
                    self.log(f"  ★ step11 state={s11[:60]}...")
                wrh11 = qs11.get("workflowResultHandle", [None])[0]
                if wrh11:
                    self._step11_workflow_result_handle = wrh11
                    self.log(f"  ★ step11 workflowResultHandle={wrh11}")
        else:
            self.log(f"  ⚠️ stepId={d.get('stepId')}, 可能需要额外步骤")
        return d

    # ═══ Step 12: Kiro Web Portal OIDC Auth Code Flow → 获取 accessToken + sessionToken ═══
    # ★ 旧版 Device Auth 流程已注释掉 (不适用于 view.awsapps.com SPA)
    # def step12_get_tokens_device_auth(self):
    #     """旧版: OIDC Device Authorization 流程 (已弃用)
    #     问题: view.awsapps.com 是 SPA, device auth 页面需要独立 SSO session,
    #     纯协议无法完成设备授权确认. 改用 OIDC Auth Code Flow."""
    #     pass
    def step12_get_tokens(self):
        """通过 Kiro Web Portal OIDC Authorization Code Flow 获取 tokens.
        
        HAR 抓包分析的真实流程:
        12a: POST portal.sso/auth/sso-token (authCode=workflowResultHandle, state=step11_state)
             → 返回 JWE bearer token (sessionToken) + redirectUrl
        12b: GET portal.sso/token/whoAmI (验证 bearer token)
        12c: POST oidc/authentication_result (bearer token + orchestrator_id)
             → 返回 location (含 authorization_resumption_context)
        12d: GET oidc/authorize?authorization_resumption_context=...
             → 302 redirect 到 app.kiro.dev/signin/oauth?code=...&state=...
        12e: POST app.kiro.dev ExchangeToken (CBOR: code + codeVerifier + state)
             → 返回 accessToken + csrfToken
        """
        PORTAL = "https://portal.sso.us-east-1.amazonaws.com"
        OIDC = "https://oidc.us-east-1.amazonaws.com"
        self.log("Step 12: OIDC Auth Code Flow → 获取 tokens...")

        if not self._orchestrator_id:
            self.log("  ℹ️ orchestrator_id missing before Step 12, trying logged-in InitiateLogin retry")
            self._refresh_oidc_context_after_login()
        if self._app_oauth_code:
            direct_tokens = self._exchange_app_oauth_code()
            if direct_tokens:
                return direct_tokens

        # 检查必要数据
        if not self._portal_csrf_token:
            self.log("  ❌ 缺少 portal csrfToken (step 2)")
            return None
        auth_candidates = []
        if self._step10_workflow_result_handle and self._step10_state:
            auth_candidates.append({
                "name": "step10",
                "authCode": self._step10_workflow_result_handle,
                "state": self._step10_state,
            })
        if self._step11_workflow_result_handle and self._step11_state:
            auth_candidates.append({
                "name": "step11",
                "authCode": self._step11_workflow_result_handle,
                "state": self._step11_state,
            })
        if not auth_candidates and self._workflow_result_handle and self._step11_state:
            auth_candidates.append({
                "name": "legacy",
                "authCode": self._workflow_result_handle,
                "state": self._step11_state,
            })
        if not auth_candidates:
            self.log("  ❌ 缺少可用的 workflowResultHandle/state 组合")
            return None

        sso_h = {
            **UA,
            "accept": "application/json, text/plain, */*",
            "content-type": "application/x-www-form-urlencoded",
            "x-amz-sso-csrf-token": self._portal_csrf_token,
            "origin": "https://view.awsapps.com",
            "referer": "https://view.awsapps.com/",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        }
        auth_result_h = {
            **UA,
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://view.awsapps.com",
            "referer": "https://view.awsapps.com/",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        }
        exchange_h = self._kiro_rpc_headers()

        last_error = ""
        for candidate in auth_candidates:
            auth_code = candidate["authCode"]
            state = candidate["state"]
            self.log(f"  12a: POST portal.sso/auth/sso-token ({candidate['name']})...")
            sso_body = urlencode({
                "authCode": auth_code,
                "state": state,
                "orgId": "view",
            })
            self.log(f"  authCode={auth_code}")
            self.log(f"  state={state[:60]}...")
            self.log(f"  csrfToken={self._portal_csrf_token}")
            r = self.s.post(f"{PORTAL}/auth/sso-token", headers=sso_h, data=sso_body)
            self.log(f"  Status: {r.status_code}")
            if r.status_code != 200:
                last_error = f"sso-token {candidate['name']} failed: {r.status_code} {r.text[:500]}"
                self.log(f"  ❌ {last_error}")
                continue
            try:
                sso_resp = r.json()
            except Exception as e:
                last_error = f"sso-token {candidate['name']} json failed: {e}"
                self.log(f"  ❌ {last_error}")
                continue
            bearer_token = sso_resp.get("token", "")
            sso_redirect = sso_resp.get("redirectUrl", "")
            if not bearer_token:
                last_error = f"sso-token {candidate['name']} returned no bearer token"
                self.log(f"  ❌ {last_error}: {json.dumps(sso_resp, ensure_ascii=False)[:300]}")
                continue
            self.log(f"  ✅ bearer token (sessionToken)={bearer_token[:60]}...")
            self.log(f"  redirectUrl={sso_redirect[:160]}...")

            if sso_redirect and "view.awsapps.com" in sso_redirect:
                clean_redir = sso_redirect.split('#')[0] if '#' in sso_redirect else sso_redirect
                self.log("  12a2: GET view.awsapps.com (建立 SSO session)...")
                r2 = self.s.get(clean_redir, headers={**UA, "accept": "text/html",
                    "referer": "https://us-east-1.signin.aws/"})
                self.log(f"  view.awsapps status: {r2.status_code}")

            orch_id = self._orchestrator_id
            if sso_redirect:
                p_redir = urlparse(sso_redirect)
                fqs = parse_qs(p_redir.fragment.lstrip("#/?")) if p_redir.fragment else {}
                qs_redir = parse_qs(p_redir.query)
                redirect_cb = self._pick_query_value(qs_redir, fqs, keys=("callback_url",))
                redirect_orch = self._pick_query_value(
                    qs_redir,
                    fqs,
                    keys=("orchestrator_id", "orchestration_id", "orchestrationId"),
                )
                if redirect_cb:
                    self._callback_url = redirect_cb
                    self.log(f"  ★ callback_url={redirect_cb}")
                if redirect_orch:
                    orch_id = redirect_orch
                    self._orchestrator_id = redirect_orch
                    self.log(f"  ★ 更新 orchestrator_id={redirect_orch[:60]}...")
                elif candidate["name"] == "step10":
                    self.log(
                        "  ℹ️ step10 sso redirect 未直接提供 orchestration id，继续尝试下一组参数"
                    )
                    continue
                else:
                    self.log(
                        "  ℹ️ sso redirect 未直接提供 orchestration id，query keys="
                        f"{sorted(qs_redir.keys())}, fragment keys={sorted(fqs.keys())}"
                    )
            if not orch_id:
                self.log("  ℹ️ candidate has no orchestrator_id, retrying InitiateLogin with current SSO session")
                self._refresh_oidc_context_after_login()
                if self._app_oauth_code:
                    direct_tokens = self._exchange_app_oauth_code()
                    if direct_tokens:
                        return direct_tokens
                orch_id = self._orchestrator_id
            if not orch_id and bearer_token:
                self.log("  12fallback: no orchestrator_id, trying device auth with sessionToken...")
                device_tokens = self.step12f_device_auth(bearer_token)
                if device_tokens:
                    self.log("  ✅ device auth fallback obtained renewable OIDC credentials")
                    return device_tokens
            if not orch_id:
                last_error = f"{candidate['name']} missing orchestrator_id"
                self.log(f"  ❌ {last_error}")
                continue

            self.log("  12b: GET portal.sso/token/whoAmI...")
            whoami_h = {
                **UA,
                "accept": "application/json, text/plain, */*",
                "authorization": f"Bearer {bearer_token}",
                "origin": "https://view.awsapps.com",
                "referer": "https://view.awsapps.com/",
                "sec-fetch-site": "cross-site",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
            }
            r = self.s.get(f"{PORTAL}/token/whoAmI", headers=whoami_h)
            self.log(f"  whoAmI status: {r.status_code}")
            if r.status_code == 200:
                try:
                    whoami = r.json()
                    self.log(f"  ✅ whoAmI: {json.dumps(whoami, ensure_ascii=False)[:200]}")
                except Exception:
                    pass

            self.log("  12c: POST oidc/authentication_result...")
            auth_headers = dict(auth_result_h)
            auth_headers["x-amz-sso_bearer_token"] = bearer_token
            auth_headers["x-amz-sso-bearer-token"] = bearer_token
            r = self.s.post(
                f"{OIDC}/authentication_result",
                headers=auth_headers,
                json={"orchestrator_id": orch_id},
            )
            self.log(f"  Status: {r.status_code}")
            if r.status_code != 200:
                last_error = f"authentication_result {candidate['name']} failed: {r.status_code} {r.text[:500]}"
                self.log(f"  ❌ {last_error}")
                continue
            ar_resp = r.json()
            auth_location = ar_resp.get("location", "")
            if not auth_location:
                last_error = f"authentication_result {candidate['name']} returned no location"
                self.log(f"  ❌ {last_error}: {json.dumps(ar_resp, ensure_ascii=False)[:300]}")
                continue
            self.log(f"  ✅ location={auth_location[:120]}...")

            self.log("  12d: GET authorize (follow redirect → code)...")
            r = self.s.get(auth_location, headers={**UA, "accept": "text/html",
                "referer": "https://view.awsapps.com/"}, allow_redirects=False)
            self.log(f"  Status: {r.status_code}")
            redirect_loc = r.headers.get("location") or r.headers.get("Location", "")
            if not redirect_loc:
                last_error = f"authorize {candidate['name']} returned no redirect"
                self.log(f"  ❌ {last_error}, status={r.status_code}")
                continue
            self.log(f"  ✅ redirect → {redirect_loc[:150]}...")

            p_loc = urlparse(redirect_loc)
            qs_loc = parse_qs(p_loc.query)
            final_code = qs_loc.get("code", [None])[0]
            redirect_state = qs_loc.get("state", [None])[0] or self.state
            if not final_code:
                last_error = f"authorize {candidate['name']} redirect missing code"
                self.log(f"  ❌ {last_error}")
                continue
            self.log(f"  ✅ auth_code={final_code[:60]}...")
            self.log(f"  ✅ redirect_state={redirect_state[:60]}...")

            self.log("  12e: POST ExchangeToken (CBOR)...")
            exchange_body = cbor2.dumps({
                "code": final_code,
                "codeVerifier": self.cv,
                "idp": "BuilderId",
                "redirectUri": f"{KIRO}/signin/oauth",
                "state": redirect_state,
            })
            r = self.s.post(
                f"{KIRO}/service/KiroWebPortalService/operation/ExchangeToken",
                headers=exchange_h,
                data=exchange_body,
                cookies={"kiro-visitor-id": self.vid},
            )
            self.log(f"  Status: {r.status_code}")
            if r.status_code != 200:
                last_error = f"ExchangeToken {candidate['name']} failed: {r.status_code}"
                self.log(f"  ❌ {last_error}")
                try:
                    self.log(f"  {r.text[:500]}")
                except Exception:
                    self.log(f"  (binary response, len={len(r.content)})")
                continue
            try:
                resp_data = cbor2.loads(r.content)
            except Exception as e:
                last_error = f"ExchangeToken {candidate['name']} CBOR failed: {e}"
                self.log(f"  ❌ {last_error}")
                continue
            normalized = self._normalize_exchange_token_response(
                resp_data,
                session_token=bearer_token,
                source=f"ExchangeToken {candidate['name']}",
            )
            if normalized:
                # ★ HAR-derived: real Chrome fires dashboard pageView beacon
                # right after ExchangeToken returns accessToken (entry [124]).
                try:
                    self._send_kiro_telemetry("page_view_dashboard")
                except Exception:
                    pass
                return self._upgrade_kiro_chat_token(
                    normalized,
                    source=f"ExchangeToken {candidate['name']}",
                )
            last_error = f"ExchangeToken {candidate['name']} missing accessToken/profileArn"
            continue

        self.log(f"  ❌ Step 12 最终失败: {last_error or 'unknown error'}")
        return None

    # ═══ Step 12f-12j: OIDC Device Authorization Flow → 获取 refreshToken ═══
    # 逆向自 view.awsapps.com SPA main.js + Chrome 扩展 AWS-BuildID-Auto-For-Ext
    # SPA 中 OIDC class (class v) 的 device auth API:
    #   - GET  /device_verification?user_code=...     (ValidateUserCode, withBearerToken:false)
    #   - GET  /consent_details?device_context_id=...&client_id=...  (ListConsentDetails, withBearerToken:false)
    #   - POST /device_authorization/accept_user_code  (AcceptUserCode, JSON, withBearerToken:false)
    #   - POST /device_authorization/associate_token   (AssociateTokenWithDevice, JSON, withBearerToken:false)
    # SPA 通过 view.awsapps.com/api/oidc/ 代理调用, 代理用 SSO session cookie 认证
    # 我们直接调用 portal.sso 用 bearer token 认证
    def step12f_device_auth(self, bearer_token):
        """通过 OIDC Device Authorization 获取 refreshToken.
        
        流程:
        12f: POST oidc/client/register → clientId, clientSecret
        12g: POST oidc/device_authorization → deviceCode, userCode
        12h: 模拟 SPA 设备授权确认 (用 bearer token 调用 portal.sso API):
             - GET  /device_verification?user_code=...
             - GET  /consent_details?device_context_id=...&client_id=...
             - POST /device_authorization/accept_user_code
             - POST /device_authorization/associate_token
        12i: POST oidc/token → accessToken(OIDC), refreshToken
        """
        OIDC = "https://oidc.us-east-1.amazonaws.com"
        PORTAL = "https://portal.sso.us-east-1.amazonaws.com"
        self.log("Step 12f: OIDC Device Auth → refreshToken...")

        # ── 12f: POST oidc/client/register ──
        self.log("  12f: POST oidc/client/register...")
        reg_h = {
            "content-type": "application/json",
            "user-agent": "aws-sdk-rust/1.3.9 os/windows lang/rust/1.87.0",
            "x-amz-user-agent": "aws-sdk-rust/1.3.9 ua/2.1 api/ssooidc/1.88.0 "
                "os/windows lang/rust/1.87.0 m/E app/AmazonQ-For-CLI",
            "amz-sdk-request": "attempt=1; max=3",
            "amz-sdk-invocation-id": _uuid(),
        }
        reg_body = {
            "clientName": "Kiro Proxy",
            "clientType": "public",
            "scopes": [
                "codewhisperer:completions",
                "codewhisperer:analysis",
                "codewhisperer:conversations",
                "codewhisperer:transformations",
                "codewhisperer:taskassist",
            ],
            "grantTypes": [
                "urn:ietf:params:oauth:grant-type:device_code",
                "refresh_token",
            ],
            "issuerUrl": "https://view.awsapps.com/start",
        }
        r = self.s.post(f"{OIDC}/client/register", headers=reg_h,
                        json=reg_body)
        self.log(f"  Status: {r.status_code}")
        if r.status_code != 200:
            self.log(f"  ❌ client/register 失败: {r.text[:300]}")
            return None
        reg_resp = r.json()
        client_id = reg_resp.get("clientId", "")
        client_secret = reg_resp.get("clientSecret", "")
        if not client_id or not client_secret:
            self.log(f"  ❌ 无 clientId/clientSecret")
            return None
        self.log(f"  ✅ clientId={client_id[:40]}...")

        # ── 12g: POST oidc/device_authorization ──
        self.log("  12g: POST oidc/device_authorization...")
        da_h = {**reg_h, "amz-sdk-invocation-id": _uuid()}
        da_body = {
            "clientId": client_id,
            "clientSecret": client_secret,
            "startUrl": "https://view.awsapps.com/start",
        }
        r = self.s.post(f"{OIDC}/device_authorization", headers=da_h,
                        json=da_body)
        self.log(f"  Status: {r.status_code}")
        if r.status_code != 200:
            self.log(f"  ❌ device_authorization 失败: {r.text[:300]}")
            return None
        da_resp = r.json()
        device_code = da_resp.get("deviceCode", "")
        user_code = da_resp.get("userCode", "")
        interval = da_resp.get("interval", 1)
        verification_uri = da_resp.get("verificationUriComplete", "")
        if not device_code or not user_code:
            self.log(f"  ❌ 无 deviceCode/userCode")
            return None
        self.log(f"  ✅ userCode={user_code}")
        self.log(f"  ✅ verificationUri={verification_uri[:100]}...")

        # ── 12h: 设备授权确认 (直接调用 oidc.amazonaws.com) ──
        # 真实流程 (来自浏览器抓包):
        #   12h-1: POST oidc/device_authorization/accept_user_code
        #          body: {userCode, userSessionId(bearer_token)} → deviceContext
        #   12h-2: POST portal.sso/session/device → device session token
        #   12h-3: POST oidc/consent_details (body, 含 userSessionId=device_token)
        #   12h-4: POST oidc/device_authorization/associate_token → {location:null}
        self.log("  12h: 设备授权确认 (直接调用 oidc.amazonaws.com)...")

        oidc_h = {
            **UA,
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "origin": "https://view.awsapps.com",
            "referer": "https://view.awsapps.com/",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        }

        # 12h-1: POST oidc/device_authorization/accept_user_code
        self.log(f"  12h-1: POST accept_user_code (userCode={user_code})...")
        r = self.s.post(
            f"{OIDC}/device_authorization/accept_user_code",
            headers=oidc_h,
            json={"userCode": user_code, "userSessionId": bearer_token})
        self.log(f"  Status: {r.status_code} {r.text[:300]}")
        if r.status_code != 200:
            self.log(f"  ❌ accept_user_code 失败")
            return None
        accept_resp = r.json()
        device_context = accept_resp.get("deviceContext", {})
        dc_id = device_context.get("deviceContextId", "")
        dc_client_id = device_context.get("clientId", client_id)
        dc_client_type = device_context.get("clientType", "public")
        self.log(f"  ✅ deviceContextId={dc_id[:60]}...")

        # 12h-2: POST portal.sso/session/device → device session token
        self.log("  12h-2: POST portal.sso/session/device...")
        r = self.s.post(
            f"{PORTAL}/session/device",
            headers={**UA, "accept": "application/json, text/plain, */*",
                     "content-type": "application/json",
                     "authorization": f"Bearer {bearer_token}",
                     "origin": "https://view.awsapps.com",
                     "referer": "https://view.awsapps.com/",
                     "sec-fetch-site": "cross-site",
                     "sec-fetch-mode": "cors"},
            json={})
        self.log(f"  Status: {r.status_code} {r.text[:300]}")
        device_token = bearer_token
        if r.status_code == 200:
            device_token = r.json().get("token", bearer_token)
        self.log(f"  ✅ device_token={device_token[:60]}...")

        # 12h-3: POST oidc/consent_details
        self.log("  12h-3: POST consent_details...")
        r = self.s.post(
            f"{OIDC}/consent_details",
            headers=oidc_h,
            json={"deviceContextId": dc_id, "clientId": dc_client_id,
                  "clientType": dc_client_type, "userSessionId": device_token})
        self.log(f"  Status: {r.status_code} {r.text[:300]}")
        if r.status_code == 200:
            self.log(f"  ✅ consent_details OK")

        # 12h-4: POST oidc/device_authorization/associate_token
        self.log("  12h-4: POST associate_token...")
        r = self.s.post(
            f"{OIDC}/device_authorization/associate_token",
            headers=oidc_h,
            json={"deviceContext": {"deviceContextId": dc_id,
                                    "clientId": dc_client_id,
                                    "clientType": dc_client_type},
                  "userSessionId": device_token})
        self.log(f"  Status: {r.status_code} {r.text[:300]}")
        if r.status_code not in (200, 204):
            self.log(f"  ❌ associate_token 失败")
            return None
        self.log(f"  ✅ associate_token 完成")

        # ── 12i: POST oidc/token → refreshToken ──
        self.log("  12i: POST oidc/token (轮询获取 refreshToken)...")
        token_h = {**reg_h, "amz-sdk-invocation-id": _uuid()}
        token_body = {
            "clientId": client_id,
            "clientSecret": client_secret,
            "deviceCode": device_code,
            "grantType": "urn:ietf:params:oauth:grant-type:device_code",
        }
        # 轮询 (最多 60 秒)
        poll_start = time.time()
        poll_timeout = 60
        poll_interval = max(interval, 1)
        oidc_token = None
        while time.time() - poll_start < poll_timeout:
            r = self.s.post(f"{OIDC}/token", headers=token_h, json=token_body)
            if r.status_code == 200:
                oidc_token = r.json()
                break
            try:
                err = r.json()
                err_code = err.get("error", "")
                if err_code == "authorization_pending":
                    self.log(f"  轮询中... (authorization_pending)")
                elif err_code == "slow_down":
                    poll_interval = min(poll_interval + 1, 10)
                    self.log(f"  slow_down, interval={poll_interval}s")
                else:
                    self.log(f"  ❌ token 错误: {err_code} - {err.get('error_description','')}")
                    return None
            except:
                self.log(f"  ❌ token 响应异常: {r.status_code} {r.text[:200]}")
                return None
            time.sleep(poll_interval)

        if not oidc_token:
            self.log("  ❌ token 轮询超时")
            return None

        oidc_access = oidc_token.get("accessToken", "")
        refresh_token = oidc_token.get("refreshToken", "")
        expires_in = oidc_token.get("expiresIn", 0)
        self.log(f"  ✅ OIDC accessToken={oidc_access[:60]}...")
        self.log(f"  ✅ refreshToken={refresh_token[:60]}...")
        return {
            "clientId": client_id,
            "clientSecret": client_secret,
            "accessToken": oidc_access,
            "refreshToken": refresh_token,
            "sessionToken": bearer_token,
            "expiresIn": expires_in,
        }

# ═══════════════════════════════════════════
#  TechFlow 邮箱 (已弃用, 注释保留)
# ═══════════════════════════════════════════
#
# def create_techflow_email():
#     chars = string.ascii_lowercase + string.digits
#     local = "".join(random.choice(chars) for _ in range(random.randint(8, 13)))
#     return f"{local}@{TECHFLOW_DOMAIN}"
#
# def _techflow_headers():
#     return {
#         "accept": "application/json",
#         "x-admin-auth": TECHFLOW_ADMIN_AUTH,
#         "x-fingerprint": "6703363b6fbfa14e379ca8743835abf9",
#         "x-lang": "zh",
#     }
#
# def wait_for_otp_techflow(email, timeout=120, tag=""):
#     prefix = f"[{tag}] " if tag else ""
#     print(f"{prefix}  等待验证码邮件 (最多{timeout}s)...")
#     s = curl_requests.Session()
#     h = _techflow_headers()
#     start = time.time()
#     seen_ids = set()
#     while time.time() - start < timeout:
#         try:
#             r = s.get(f"{TECHFLOW_API}/admin/mails",
#                       params={"limit": 10, "offset": 0},
#                       headers=h, timeout=15, impersonate="chrome146")
#             if r.status_code == 200:
#                 data = r.json()
#                 for mail in data.get("results", []):
#                     mid = mail.get("id")
#                     addr = mail.get("address", "")
#                     if mid in seen_ids: continue
#                     seen_ids.add(mid)
#                     if addr.lower() != email.lower(): continue
#                     raw = mail.get("raw", "")
#                     source = mail.get("source", "")
#                     if "signin.aws" not in source and "amazon" not in source.lower():
#                         if "signin.aws" not in raw and "verification" not in raw.lower():
#                             continue
#                     for pat in [r"验证码[:：]\s*(\d{6})",
#                                 r"verification code is:?\s*(\d{6})",
#                                 r"Verification code:?\s*(\d{6})",
#                                 r">\s*(\d{6})\s*<",
#                                 r"\b(\d{6})\b"]:
#                         m = re.search(pat, raw, re.IGNORECASE)
#                         if m:
#                             code = m.group(1)
#                             print(f"{prefix}  ✅ 验证码: {code}")
#                             return code
#         except: pass
#         elapsed = int(time.time() - start)
#         print(f"{prefix}  等待中... ({elapsed}s/{timeout}s)")
#         time.sleep(3)
#     print(f"{prefix}  ❌ 验证码超时")
#     return None

# ═══════════════════════════════════════════
#  qqemail.eu.org 临时邮箱 API (已弃用, 注释保留)
# ═══════════════════════════════════════════
# QQEMAIL_API = "https://qqemail.eu.org/api"
# QQEMAIL_DOMAIN = "qqemail.eu.org"
# QQEMAIL_COOKIES = (
#     "__Host-authjs.csrf-token=....; "
#     "__Secure-authjs.callback-url=....; "
#     "__Secure-authjs.session-token=...."
# )
#
# def _qqemail_headers():
#     return {
#         "accept": "*/*",
#         "content-type": "application/json",
#         "origin": f"https://{QQEMAIL_DOMAIN}",
#         "referer": f"https://{QQEMAIL_DOMAIN}/moe",
#         "cookie": QQEMAIL_COOKIES,
#         **UA,
#     }
#
# def create_qqemail():
#     """创建 qqemail 临时邮箱, 返回 (email, inbox_id)"""
#     chars = string.ascii_lowercase + string.digits
#     local = "".join(random.choice(chars) for _ in range(random.randint(8, 13)))
#     h = _qqemail_headers()
#     body = {"name": local, "domain": QQEMAIL_DOMAIN, "expiryTime": 0}
#     r = curl_requests.post(f"{QQEMAIL_API}/emails/generate",
#                            headers=h, json=body, impersonate="chrome146")
#     if r.status_code != 200: return None, None
#     d = r.json()
#     return d.get("email") or f"{local}@{QQEMAIL_DOMAIN}", d.get("id")
#
# def wait_for_otp_qqemail(inbox_id, timeout=120, tag=""):
#     """轮询 qqemail: GET /api/emails/{inbox_id} → message id
#        → GET /api/emails/{inbox_id}/{mid} → 邮件详情"""
#     h = _qqemail_headers()
#     prefix = f"[{tag}] " if tag else ""
#     start = time.time(); seen_ids = set()
#     while time.time() - start < timeout:
#         try:
#             r = curl_requests.get(f"{QQEMAIL_API}/emails/{inbox_id}",
#                                   headers=h, timeout=15, impersonate="chrome146")
#             if r.status_code == 200:
#                 for mail in r.json().get("messages", []):
#                     mid = mail.get("id")
#                     if not mid or mid in seen_ids: continue
#                     seen_ids.add(mid)
#                     r2 = curl_requests.get(f"{QQEMAIL_API}/emails/{inbox_id}/{mid}",
#                                            headers=h, timeout=15, impersonate="chrome146")
#                     if r2.status_code != 200: continue
#                     detail = r2.json().get("message", r2.json())
#                     combined = detail.get("subject","") + " " + (
#                         detail.get("content","") or detail.get("html","") or "")
#                     for pat in [r">\s*(\d{6})\s*<", r"\b(\d{6})\b"]:
#                         m = re.search(pat, combined)
#                         if m: return m.group(1)
#         except: pass
#         time.sleep(3)
#     return None

# ═══════════════════════════════════════════
#  laoudo.com 邮箱 API (当前使用)
# ═══════════════════════════════════════════
LAOUDO_API = "https://laoudo.com/api/email"
LAOUDO_ACCOUNT_ID = ""  # 在全局配置中设置
LAOUDO_AUTH = ""  # 在全局配置中设置
# 固定邮箱地址
LAOUDO_EMAIL = ""  # 在全局配置中设置

def _laoudo_headers():
    return {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh",
        "authorization": LAOUDO_AUTH,
        "referer": "https://laoudo.com/inbox",
        **UA,
    }

def wait_for_otp(account_id=None, timeout=120, tag=""):
    """轮询 laoudo.com 收件箱, 提取 AWS 验证码.
    GET /api/email/list?accountId={account_id}&...
    account_id: laoudo 账户 ID (默认 LAOUDO_ACCOUNT_ID)"""
    if not account_id:
        account_id = LAOUDO_ACCOUNT_ID
    prefix = f"[{tag}] " if tag else ""
    print(f"{prefix}  等待验证码邮件 (最多{timeout}s)...")
    h = _laoudo_headers()
    start = time.time()
    seen_ids = set()
    while time.time() - start < timeout:
        try:
            params = {
                "accountId": account_id,
                "allReceive": 0,
                "emailId": 0,
                "timeSort": 0,
                "size": 50,
                "type": 0,
            }
            r = curl_requests.get(f"{LAOUDO_API}/list",
                                  params=params, headers=h,
                                  timeout=15, impersonate="chrome146")
            if r.status_code == 200:
                data = r.json()
                # laoudo 返回格式: {"code":200,"data":{"list":[...]}} 或直接 list
                mail_list = data
                if isinstance(data, dict):
                    mail_list = (data.get("data", {}).get("list")
                                 or data.get("list")
                                 or data.get("data", []))
                if not isinstance(mail_list, list):
                    mail_list = []
                for mail in mail_list:
                    mid = mail.get("id") or mail.get("emailId")
                    if not mid or mid in seen_ids: continue
                    seen_ids.add(mid)
                    # 从邮件摘要/内容中提取验证码
                    subject = str(mail.get("subject", "") or "")
                    content = str(mail.get("content", "") or
                                  mail.get("html", "") or
                                  mail.get("body", "") or
                                  mail.get("text", "") or "")
                    from_addr = str(mail.get("fromAddress", "") or
                                    mail.get("from", "") or "")
                    # 只处理 AWS 相关邮件
                    combined = subject + " " + content
                    if ("amazon" not in combined.lower() and
                        "aws" not in combined.lower() and
                        "signin" not in combined.lower() and
                        "verification" not in combined.lower()):
                        continue
                    for pat in [r"验证码[:：]\s*(\d{6})",
                                r"verification code is:?\s*(\d{6})",
                                r"Verification code:?\s*(\d{6})",
                                r">\s*(\d{6})\s*<",
                                r"\b(\d{6})\b"]:
                        m = re.search(pat, combined, re.IGNORECASE)
                        if m:
                            code = m.group(1)
                            print(f"{prefix}  ✅ 验证码: {code}")
                            return code
        except Exception as e:
            print(f"{prefix}  ⚠️ 查询邮件异常: {e}")
        elapsed = int(time.time() - start)
        print(f"{prefix}  等待中... ({elapsed}s/{timeout}s)")
        time.sleep(3)
    print(f"{prefix}  ❌ 验证码超时")
    return None


def main():
    print("=" * 50)
    print("Kiro / AWS Builder ID 自动注册工具 v10")
    print("(v8核心 + laoudo.com 邮箱)")
    print("=" * 50)
    mode = input("模式: 1=手动输入邮箱 2=laoudo固定邮箱 (默认2): ").strip()
    proxy = input("代理 (留空跳过): ").strip() or None
    pwd = input("密码 (留空自动生成): ").strip() or None
    name = input("显示名称 (留空默认 Kiro User): ").strip() or "Kiro User"

    mail_token = None
    if mode == "1":
        email = input("请输入邮箱: ").strip()
        if not email: print("邮箱不能为空"); return
    else:
        email = LAOUDO_EMAIL
        mail_token = LAOUDO_ACCOUNT_ID
        print(f"✅ 邮箱: {email} (laoudo accountId={LAOUDO_ACCOUNT_ID})")

    reg = KiroRegister(proxy=proxy, tag="REG-1")
    ok, info = reg.register(email, pwd=pwd, name=name,
                            mail_token=mail_token)
    if ok:
        print(f"\n✅ 注册成功!")
        print(f"  邮箱: {info['email']}")
        print(f"  密码: {info['password']}")
        if info.get('accessToken'):
            print(f"  accessToken: {info['accessToken'][:60]}...")
            print(f"  sessionToken: {info['sessionToken'][:60]}...")
        if info.get('refreshToken'):
            print(f"  clientId: {info['clientId'][:40]}...")
            print(f"  clientSecret: {info['clientSecret'][:40]}...")
            print(f"  refreshToken: {info['refreshToken'][:60]}...")
        with open("kiro_accounts.txt", "a") as f:
            rec = json.dumps({
                "email": info['email'],
                "password": info['password'],
                "accessToken": info.get('accessToken', ''),
                "sessionToken": info.get('sessionToken', ''),
                "clientId": info.get('clientId', ''),
                "clientSecret": info.get('clientSecret', ''),
                "refreshToken": info.get('refreshToken', ''),
            }, ensure_ascii=False)
            f.write(rec + "\n")
        print("  已保存到 kiro_accounts.txt")
    else:
        print(f"\n❌ 注册失败: {info.get('error')}")

if __name__ == "__main__":
    main()
