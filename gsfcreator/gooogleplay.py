from Crypto.Util import asn1
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_OAEP

import requests
from base64 import b64decode, urlsafe_b64encode
from itertools import chain

from . import googleplay_pb2, config, utils

ssl_verify = True

class LoginError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class RequestError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class GooglePlayAPI(object):
    """Google Play Unofficial API Class
    Usual APIs methods are login(), search(), details(), bulkDetails(),
    download(), browse(), reviews() and list()."""

    BASE = "https://android.clients.google.com/"
    FDFE = BASE + "fdfe/"
    UPLOADURL = FDFE + "uploadDeviceConfig"
    SEARCHURL = FDFE + "search"
    CHECKINURL = BASE + "checkin"
    AUTHURL = BASE + "auth"

    proxies_config = None

    def __init__(self, debug=False, device_codename='bacon',
                 locale=None, timezone=None,
                 sim_operator=None, cell_operator=None,
                 proxies_config=None):
        self.authSubToken = None
        self.gsfId = None
        self.debug = debug
        self.proxies_config = proxies_config
        self.deviceBuilder = config.DeviceBuilder(device_codename)
        self.deviceBuilder.setLocale(locale)
        if timezone is not None:
            self.deviceBuilder.timezone = timezone
        if sim_operator is not None:
            self.deviceBuilder.device['simoperator'] = sim_operator
        if cell_operator is not None:
            self.deviceBuilder.device['celloperator'] = cell_operator

    def encrypt_password(self, login, passwd):
        """Encrypt the password using the google publickey, using
        the RSA encryption algorithm"""

        binaryKey = b64decode(config.GOOGLE_PUBKEY)
        i = utils.readInt(binaryKey, 0)
        modulus = utils.toBigInt(binaryKey[4:][0:i])
        j = utils.readInt(binaryKey, i+4)
        exponent = utils.toBigInt(binaryKey[i+8:][0:j])

        seq = asn1.DerSequence()
        seq.append(modulus)
        seq.append(exponent)

        publicKey = RSA.importKey(seq.encode())
        cipher = PKCS1_OAEP.new(publicKey)
        combined = login.encode() + b'\x00' + passwd.encode()
        encrypted = cipher.encrypt(combined)
        h = b'\x00' + SHA.new(binaryKey).digest()[0:4]
        return urlsafe_b64encode(h + encrypted)

    def setAuthSubToken(self, authSubToken):
        self.authSubToken = authSubToken

        # put your auth token in config.py to avoid multiple login requests
        if self.debug:
            print("authSubToken: " + authSubToken)

    def getDefaultHeaders(self):
        """Return the default set of request headers, which
        can later be expanded, based on the request type"""

        headers = {"Accept-Language": self.deviceBuilder.locale.replace('_', '-'),
                   "X-DFE-Encoded-Targets": config.DFE_TARGETS,
                   "User-Agent": self.deviceBuilder.getUserAgent()}
        if self.gsfId is not None:
            headers["X-DFE-Device-Id"] = "{0:x}".format(self.gsfId)
        if self.authSubToken is not None:
            headers["Authorization"] = "GoogleLogin auth=%s" % self.authSubToken
        return headers

    def checkin(self, email, ac2dmToken):
        headers = self.getDefaultHeaders()
        headers["Content-Type"] = "application/x-protobuffer"

        request = self.deviceBuilder.getAndroidCheckinRequest()

        stringRequest = request.SerializeToString()
        res = requests.post(self.CHECKINURL, data=stringRequest,
                            headers=headers, verify=ssl_verify,
                            proxies=self.proxies_config)
        response = googleplay_pb2.AndroidCheckinResponse()
        response.ParseFromString(res.content)

        # checkin again to upload gfsid
        request2 = googleplay_pb2.AndroidCheckinRequest()
        request2.CopyFrom(request)
        request2.id = response.androidId
        request2.securityToken = response.securityToken
        request2.accountCookie.append("[" + email + "]")
        request2.accountCookie.append(ac2dmToken)
        stringRequest = request2.SerializeToString()
        requests.post(self.CHECKINURL, data=stringRequest,
                      headers=headers, verify=ssl_verify,
                      proxies=self.proxies_config)

        return response.androidId

    def uploadDeviceConfig(self):
        """Upload the device configuration of the fake device
        selected in the __init__ methodi to the google account."""

        upload = googleplay_pb2.UploadDeviceConfigRequest()
        upload.deviceConfiguration.CopyFrom(self.deviceBuilder.getDeviceConfig())
        headers = self.getDefaultHeaders()
        headers["X-DFE-Enabled-Experiments"] = "cl:billing.select_add_instrument_by_default"
        headers["X-DFE-Unsupported-Experiments"] = "nocache:billing.use_charging_poller,market_emails,buyer_currency,prod_baseline,checkin.set_asset_paid_app_field,shekel_test,content_ratings,buyer_currency_in_app,nocache:encrypted_apk,recent_changes"
        headers["X-DFE-Client-Id"] = "am-android-google"
        headers["X-DFE-SmallestScreenWidthDp"] = "320"
        headers["X-DFE-Filter-Level"] = "3"
        stringRequest = upload.SerializeToString()
        res = requests.post(self.UPLOADURL, data=stringRequest,
                            headers=headers, verify=ssl_verify,
                            proxies=self.proxies_config)
        googleplay_pb2.ResponseWrapper.FromString(res.content)

    def login(self, email=None, password=None):
        """
        Login to your Google Account and return the gsfId.

        :param email: login email
        :param password: plaintext password
        :return: gsfId
        """
        if email is not None and password is not None:
            # First time setup, where we obtain an ac2dm token and
            # upload device information

            encryptedPass = self.encrypt_password(email, password).decode('utf-8')
            # AC2DM token
            params = self.deviceBuilder.getLoginParams(email, encryptedPass)
            response = requests.post(self.AUTHURL, data=params, verify=ssl_verify,
                                     proxies=self.proxies_config)
            data = response.text.split()
            params = {}
            for d in data:
                if "=" not in d:
                    continue
                k, v = d.split("=", 1)
                params[k.strip().lower()] = v.strip()
            if "auth" in params:
                ac2dmToken = params["auth"]
            elif "error" in params:
                if "NeedsBrowser" in params["error"]:
                    raise LoginError("Security check is needed, try to visit "
                                     "https://accounts.google.com/b/0/DisplayUnlockCaptcha "
                                     "to unlock, or setup an app-specific password")
                raise LoginError("server says: " + params["error"])
            else:
                raise LoginError("Auth token not found.")

            self.gsfId = self.checkin(email, ac2dmToken)
            if self.debug:
                print("Google Services Framework Id: %s" % "{0:x}".format(self.gsfId))
            self.getAuthSubToken(email, encryptedPass)
            if self.debug:
                print("Uploading device configuration")
            self.uploadDeviceConfig()
            return self.gsfId
        else:
            raise LoginError('(email,pass) is needed')

    def getAuthSubToken(self, email, passwd):
        """
        :param email: user email
        :param passwd: plain text password
        :return: login auth token
        """
        requestParams = self.deviceBuilder.getAuthParams(email, passwd)
        response = requests.post(self.AUTHURL, data=requestParams, verify=ssl_verify,
                                 proxies=self.proxies_config)
        data = response.text.split()
        params = {}
        for d in data:
            if "=" not in d:
                continue
            k, v = d.split("=", 1)
            params[k.strip().lower()] = v.strip()
        if "token" in params:
            firstToken = params["token"]
            if self.debug:
                print('Master token: %s' % firstToken)
            secondToken = self.getSecondRoundToken(requestParams, firstToken)
            self.setAuthSubToken(secondToken)
        elif "error" in params:
            raise LoginError("server says: " + params["error"])
        else:
            raise LoginError("Auth token not found.")

    def getSecondRoundToken(self, previousParams, firstToken):
        previousParams['Token'] = firstToken
        previousParams['service'] = 'androidmarket'
        previousParams['check_email'] = '1'
        previousParams['token_request_options'] = 'CAA4AQ=='
        previousParams['system_partition'] = '1'
        previousParams['_opt_is_called_from_account_manager'] = '1'
        previousParams['google_play_services_version'] = '11518448'
        previousParams.pop('Email')
        previousParams.pop('EncryptedPasswd')
        response = requests.post(self.AUTHURL,
                                 data=previousParams,
                                 verify=ssl_verify,
                                 proxies=self.proxies_config)
        data = response.text.split()
        params = {}
        for d in data:
            if "=" not in d:
                continue
            k, v = d.split("=", 1)
            params[k.strip().lower()] = v.strip()
        if "auth" in params:
            return params["auth"]
        elif "error" in params:
            raise LoginError("server says: " + params["error"])
        else:
            raise LoginError("Auth token not found.")
