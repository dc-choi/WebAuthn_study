const publicKeyCredentialCreationOptions = { // 서버에 의해 지정된 여러 개의 필수 및 선택 필드가 포함되어 있음
    challenge: Uint8Array.from(randomStringFromServer, c => c.charCodeAt(0)),
	/**
	 * 서버에서 생성된 암호화 방식으로 무작위 바이트의 버퍼이며 "replay attacks"을 방지하기 위해 필요합니다.
	 * replay attacks: 공격자가 두 당사자 간에 메시지 스트림을 복사하고 하나 이상의 당사자에게 스트림을 재생할 때 발생합니다.
	 */
    rp: {
        name: "Duo Security",
        id: "duosecurity.com",
    },
	/**
	 * 이것은 사용자를 등록하고 인증하는 조직을 설명하는 것으로 간주될 수 있다.
	 * id는 현재 브라우저에 있는 도메인의 하위 집합이어야 합니다.
	 */
    user: {
        id: Uint8Array.from(
            "UZSL85T9AFC", c => c.charCodeAt(0)),
        name: "lee@webauthn.guide",
        displayName: "Lee",
    },
    /**
     * 이것은 현재 등록 중인 사용자에 대한 정보입니다.
     * 인증자는 ID를 사용하여 자격 증명을 사용자와 연결합니다.
     * 인증자에 저장 될 수 있으므로 개인 식별 정보를 ID로 사용하지 않는 것이 좋습니다.
     */
    pubKeyCredParams: [{alg: -7, type: "public-key"}],
    /**
     * 이것은 서버에서 허용할 수 있는 공개 키 유형을 설명하는 개체 배열입니다.
     * alg는 COSE 레지스트리에 설명된 숫자입니다.
     * 예를 들어 -7은 서버가 SHA-256 서명 알고리즘을 사용하여 타원 곡선 공개 키를 허용 함을 나타냅니다.
     */
    authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
    },
    /**
     * 이 선택적 개체는 종속 당사자가 등록에 허용된 인증자 유형을 추가로 제한할 수 있도록 도와줍니다.
     * 이 예에서는 Windows Hello 또는 Touch ID와 같은 플랫폼 인증자 대신 교차 플랫폼 인증자(유비키와 같은)를 등록하려고 합니다.
     */
    timeout: 60000,
    /**
     * 오류가 반환되기 전에 사용자가 등록 프롬프트에 응답해야 하는 시간(밀리초 단위).
     */
    attestation: "direct"
    /**
     * 인증자에서 반환되는 증명 데이터에는 사용자를 추적하는 데 사용할 수 있는 정보가 있습니다.
     * 이 옵션을 사용하면 서버가 이 등록 이벤트에 대한 증명 데이터의 중요도를 나타낼 수 있습니다.
     * 값이 "none"이면 서버가 증명에 신경 쓰지 않음을 나타냅니다.
     * "indirect" 값은 서버가 익명 증명 데이터를 허용함을 의미합니다.
     * direct는 서버가 인증자로부터 증명 데이터를 수신하려는 것을 의미합니다.
     */
};

const credential = await navigator.credentials.create({ // 새 자격증명을 만들기 위한 등록요청
    publicKey: publicKeyCredentialCreationOptions
});

console.log(credential); // PublicKeyCredential
// create() 호출에서 반환된 자격 증명 개체는 등록 이벤트의 유효성을 확인하는 데 사용되는 공용 키 및 기타 속성을 포함하는 개체

{
	id: 'ADSUllKQmbqdGtpu4sjseh4cg2TxSvrbcHDTBsv4NSSX9...',
    // 새로 생성된 자격 증명의 ID입니다.사용자를 인증할 때 자격 증명을 식별하는 데 사용됩니다.
    // ID는 여기서 base64로 인코딩된 문자열로 제공된다.
	rawId: ArrayBuffer(59),
    // 바이너리 형식의 아이디입니다.
	response: AuthenticatorAttestationResponse {
		clientDataJSON: ArrayBuffer(121),
        /**
         * 이것은 새 자격 증명을 서버 및 브라우저와 연결하기 위해 브라우저에서 인증자로 전달된 데이터를 나타냅니다.
         * 인증자는 UTF-8 바이트 배열로 제공합니다.
         */
		attestationObject: ArrayBuffer(306),
        /**
         * 이 개체에는 자격 증명 공개 키, 선택적 증명 인증서 및 등록 이벤트의 유효성을 확인하는 데 사용되는 기타 메타데이터가 포함됩니다.
         * CBOR로 인코딩된 이진 데이터입니다.
         */
	},
	type: 'public-key'
}

/**
 * 공용 키 자격 증명을 얻으면 확인을 위해 서버로 전송됩니다.
 * WebAuthn 사양은 등록 데이터의 유효성을 검사하는 19가지 절차를 설명합니다.
 * 이 절차는 서버 소프트웨어가 작성된 언어에 따라 달라집니다.
 */


// Parsing the clientDataJSON
{
    challenge: "p5aV2uHXr0AOqUk7HQitvi-Ny1....",
    // 이것은 create() 호출에 전달된 것과 동일합니다.
    // 서버는 반환된 challenge가 이 등록 이벤트에 대해 생성된 challenge와 일치하는지 확인해야 합니다.
    origin: "https://webauthn.guide",
    // 서버는 이 "origin" 문자열이 응용프로그램의 origin과 일치하는지 확인해야 합니다.
    type: "webauthn.create"
    // 서버는 이 문자열이 실제로 "webauthn.create"인지 확인합니다.
    // 다른 문자열이 제공되면 인증자가 잘못된 작업을 수행했음을 나타냅니다.
}

// Parsing the attestationObject
{
    authData: Uint8Array(196),
    // 인증자 데이터는 등록 이벤트에 대한 메타데이터와 향후 인증에 사용할 공개 키가 포함된 바이트 배열입니다.
    fmt: "fido-u2f",
    // 증명 형식을 나타냅니다.
    // 인증자는 여러 가지 방법으로 증명 데이터를 제공할 수 있습니다.
    // 이는 서버가 증명 데이터를 구문 분석하고 검증하는 방법을 나타냅니다.
    attStmt: {
        sig: Uint8Array(70),
        x5c: Array(1),
    },
	// 이것은 증명문입니다. 이 개체는 표시된 증명 형식에 따라 다르게 나타납니다.
	// 이 경우 서명 서명 및 증명 인증서 x5c가 제공됩니다.
	// 서버는 이 데이터를 사용하여 인증자로부터 받은 자격 증명 공개 키를 암호화하여 확인합니다.
	// 또한 서버는 인증서를 사용하여 취약한 것으로 추정되는 인증자를 거부할 수 있습니다.
}

// Parsing the authenticator data (Parsing authData)
{
	rpIdHash: "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVE",
	// 자격 증명의 범위가 지정되는 RP ID의 SHA-256 해시입니다.
	flags: {
	  "value": 65,
	  "up": true,
	  "uv": false,
	  "at": true,
	  "ed": false
	},
	signCount: 0,
	// 서명 카운터, 32비트 부호 없는 빅 엔디언 정수.
	attestedCredentialData: {
	// 증명된 자격 증명 데이터(있는 경우)입니다. 이 길이는 인증되는 인증 정보 ID 및 인증 정보 공개 키의 길이에 따라 달라집니다.
	  aaguid: "AAAAAAAAAAAAAAAAAAAAAA",
	  // 인증자의 AAGID입니다.
	  credentialId: "s83owuOGSCxZeyHsqHqF8oZM_F7kde53Pdnvzxhz9sQPK41SySk9JG0R8OIa1751SmNi37OX80oqIfewM9Azpg",
	  // 인증 ID
	  credentialPublicKey: {
		kty: "EC",
		alg: "ES256",
		crv: "P-256",
		x: "qcmw3NcebCb_jrRtSKpD-FKpUuupsQW2LpljWpvig10",
		y: "b1QHO_NXteqUVdbGWwaAehQQ8E1rV8ZAgYiPTV6B5-o"
	  }
	  // CTAP2 표준 CBOR 인코딩 양식을 사용하여 COSE_Key 형식으로 인코딩된 자격 증명 공개 키입니다.
	  // COSE_Key-encoded credential 공개 키는 "alg" 매개 변수를 포함해야 하며 다른 선택적 매개 변수를 포함할 수 없습니다.
	  // "alg" 매개 변수에는 COSE algorithmIdentifier 값이 포함되어야 합니다.
	  // 인코딩된 자격 증명 공개 키에는 관련 키 유형 사양에서 규정한 추가 필수 매개 변수,
	  // 즉 키 유형 "kty" 및 알고리즘 "alg"에 필요한 매개 변수가 포함되어야 합니다.
	}
}