# WebAuthn_study

## Server Requirements

<details>
<summary>FIDO Server 요구사항 자세히 보기</summary>

	1. 등록 및 증명

	서버가 등록을 지원합니다.
	등록 요청은 인증자에게 챌린지를 보내고 응답으로 CredentialCreationOptions 객체 (또는 이와 유사한)를 수신하는 형식을 취합니다.
	PublicKeyCredential의 응답 특성에는 직렬화된 clientDataJSON 특성과 직렬화된 attestationObject 특성이 모두 포함됩니다.
	역직렬화 시 증명 시 서명된 것과 기본 바이트 구조가 동일하게 유지된다는 점을 제외하고는 직렬화 형식(예: - base64url encoding)에 대한 요구사항은 없습니다.

	2-1. 증명 확인

	서버는 증명 유효성을 검사해야 합니다.
	[WebAuthn] 문서에서 증명의 유효성을 확인하는 방법을 지정합니다.
	Relying Party에 대한 요구사항은 서버에 대해 규범적입니다.
	증명 응답의 필드는 [WebAuthn] 규격의 필드 이름 또는 형식과 일치하지 않을 수 있습니다.
	응용프로그램 및 서버는 자체 필드 형식 및 이름을 협상할 수 있습니다.
	[WebAuthn] 에 설명된 이름 및 형식은 편의를 위한 것입니다.
	서버는 증명 인증서 체인의 유효성을 검사해야 합니다.
	서버는 [FIDO 메타데이터 서비스] 를 통한 증명 검증을 지원해야 합니다.
	서버는 메타데이터 속성을 기반으로 인증자에 대해 추가 인증 요소를 허용하거나, 허용하지 않거나, 요구하거나, 위험 분석을 수행하는 정책을 가질 수 있습니다.

	2.2 증명 타입

	[WebAuthn] 은 여러 증명 유형을 정의합니다.
	서버는 증명 형식 중 하나를 지원해야 합니다.

	서버가 기본 증명을 지원해야 합니다.
	서버는 자체 증명을 지원해야 합니다.
	서버가 개인 정보 CA 인증을 지원할 수 있음.
	서버는 ECDAA(타원곡선 직접 익명 증명)를 지원할 수 있습니다.

	2.3 증명 형식

	[WebAuthn] 은 여러 증명 형식을 정의하며, [WebAuthn] 에코시스템이 발전함에 따라 추가 증명 형식을 추가하기 위해 때때로 업데이트될 수 있습니다.
	서버는 하나 이상의 증명 형식을 지원해야 합니다.

	서버는 Packed Attestation을 지원해야 합니다.
	서버는 TPM Attestation을 지원해야 합니다.
	서버는 Android Key Attestation을 지원해야 합니다.
	서버는 U2F Attestation을 지원해야 합니다.
	서버는 Android SafteyNet Attestation을 지원해야 합니다.
	서버는 [WebAuthn]에서 정의한 다른 증명 형식을 지원할 수 있으며, 이러한 형식은 때때로 업데이트될 수 있습니다.
	인증자 또는 서버가 새 증명 형식을 만드는 경우 [WebAuthn]에 등록해야 합니다.

	증명 형식 예시
	{
		id: 'ADSUllKQmbqdGtpu4sjseh4cg2TxSvrbcHDTBsv4NSSX9...',
		rawId: ArrayBuffer(59),
		response: AuthenticatorAttestationResponse {
			clientDataJSON: ArrayBuffer(121),
			attestationObject: ArrayBuffer(306),
		},
		type: 'public-key'
	}

	3. 인증 및 증명

	서버는 인증을 지원해야 합니다.
	서버는 각 인증 요청에 대해 무작위 challenges 값을 사용해야 한다.
	challenges 값의 무작위성을 결정하는 것은 본 명세서의 범위를 벗어나지만(자세한 내용은 [FIDOSecRef] 참조), 동일한 challenges 값, 단조롭게 증가하는 challenges 값 또는 기타 간단한 challenges 값은 허용되지 않으며 안전하지 않으며 challenges 값 생성에 암호적으로 안전한 난수 생성기가 사용될 것으로 예상된다.
	서버가 assertion signatures의 유효성을 검사합니다.
	assertion signatures을 수신한 서버는 [WebAuthn] 에 정의된 절차를 사용하여 assertion signatures을 검증해야 합니다.
	서버는 TUP/기타 사용자 확인을 검증해야 합니다.

	4. 통신 채널 요구사항

	서버가 TLS를 구현하고 있고 토큰 바인딩을 사용할 수 있는 경우 [TokenBindingOverHttp]를 사용하여 [TokenBindingProtocol]을 구현해야 합니다.

	5. 확장자

	운영 환경에 배포할 때 이러한 방식으로 구성해야 하는 요구 사항은 없지만, 서버는 어떠한 확장도 존재하지 않고 등록 및 인증을 수행할 수 있는 동작 모드를 가져야 한다.
	서버는 확장을 지원할 수 있습니다.
	서버는 FIDO U2F와의 하위 호환성을 위해 AppId를 지원해야 합니다.
	브라우저, 플랫폼 및 기타 클라이언트는 확장을 지원하거나 지원하지 않을 수 있습니다.
	서버가 새로운 확장을 구현하는 경우 [WebAuthn]에 등록해야 합니다.

	6. 기타

	signature는 rawData 필드를 통해 계산됩니다.
	서버는 아래의 알고리즘을 필수로 구현해야합니다.
	서버는 다른 알고리즘을 구현할 수도 있습니다.

	Name: RS1
	Value: TBD (requested assignment -65535)
	Description: RSASSA-PKCS1-v1_5 w/ SHA-1
	Reference: Section 8.2 of [RFC8017]
	Status: Required

	Name: RS256
	Value: TBD (requested assignment -257)
	Description: RSASSA-PKCS1-v1_5 w/ SHA-256
	Reference: Section 8.2 of [RFC8017]
	Status: Required

	Name: ES256
	Value: -7
	Description: ECDSA using P-256 and SHA-256
	Reference: [RFC8152]
	Status: Required

	서버는 필수로 표시된 아래 곡선을 구현해야합니다.
	서버는 다른 곡선을 구현할 수도 있습니다.

	Name: P-256
	Value: 1
	Description: EC2 NIST P-256 also known as secp256r1
	Reference: [RFC8152]
	Status: Required

	설계상, 이 글 작성 시점 현재 인증자가 실제로 사용하고 있는 알고리즘과 곡선만 필수 알고리즘 및 곡선 목록에 포함됩니다.
	가능한 미래의 암호화 개발을 위해 미리 준비하고자하는 서버는 필수 알고리즘 외에도 권장 알고리즘 및 곡선을 구현하는 것을 고려해야 합니다.
	서버는 [FIDO 개인 정보 보호 원칙]을 준수해야 합니다.

	7. 전송 바인딩 프로필 (밑에 자세하게 설명)
	이 섹션은 비규범적입니다.

	7.1 소개
	이 문서에는 FIDO2 서버에 대한 비표준, 제안 된 REST API가 포함되어 있습니다.
	이 인터페이스는 필수는 아니지만 FIDO2 적합성 테스트 도구에 사용되는 인터페이스로, 서버는 적합성 테스트 도구에 의해 이러한 메시지가 검증될 수 있도록 표준 방식으로 메시지를 수신하고 보낼 수 있습니다.

	FIDO2 사양과 마찬가지로 여기에 설명된 인터페이스는 [WebAuthn] 사양에 크게 의존합니다.
	이 문서의 명명법은 WebAuthn의 명명법을 따르며 서버와 송수신되는 메시지를 정의하기 위해 인터페이스 정의 언어(IDL)를 재사용한다.

	이 문서는 등록, 인증 및 공통의 세 가지 섹션으로 나뉩니다.
	등록 및 인증 섹션에는 이러한 작업과 관련된 메시지가 포함되며 공통 섹션에는 등록 및 인증에 공통적인 메시지 및 데이터 형식이 포함됩니다.

</details>

<details>
<summary>공통 IDL: ServerResponse</summary>

	dictionary ServerResponse {
		required Status status;
		required DOMString errorMessage = "";
	}

	required status - 응답 상태를 설명합니다. "확인" 또는 "실패"로 설정할 수 있습니다.

	required errorMessage - status가 "실패"로 설정된 경우 이 필드는 비워둘 수 없습니다.

</details>

## create flow

![Sequence diagrams](https://github.com/dc-choi/WebAuthn_study/blob/master/img/reg.png)

	이 절에서는 클라이언트와 서버 간에 교환되는 등록 메시지에 대한 간략한 개요와 이러한 메시지의 예, 그리고 메시지의 IDL 정의로 결론을 설명합니다.
	등록은 WebAuthn 명명법으로 인해 "자격 증명 작성"이라고도 합니다.

	등록 흐름은 총 4개의 메시지에 대해 두 단계로 나뉩니다.
	첫 번째 단계는 클라이언트가 서버에 ServerPublicKeyCredentialCreationOptionsRequest을 보내고 서버가 ServerPublicKeyCredentialCreationOptionsResponse을 받는 "Credential Creation Options"을 검색하는 것입니다.
	이러한 옵션은 WebAuthn의 navigator.credentials.create()와 함께 사용되며, 특히 MITM(Man in the Middle) 보호를 위해 서버가 반드시 생성해야 하는 문제에서 사용됩니다.
	navigator.credentials.create()가 완료되면 해당 호출에서 생성된 사전이 ServerPublicKeyCredential로 서버로 다시 전송되고 응답 필드가 ServerAuthenticatorAttestationResponse로 설정됩니다.
	ServerAuthenticatorAttestationResponse는 일반적인 ServerAuthenticatorResponse를 확장하며, 이는 아래 "공통" 섹션에 설명되어 있습니다.
	서버는 [Webauthn] 사양의 섹션 7.1에 설명된 알고리즘에 따라 challenges, origins, signatures 및 나머지 서버 AuthenticatorAttenticationResponse의 유효성을 검사하고 적절한 서버 응답 메시지로 응답합니다.

<details>
<summary>API: 인증 정보 생성 옵션</summary>

	Request:
	URL: /attestation/options
	Method: POST
	URL Params: None
	Body: application/json formatted ServerPublicKeyCredentialCreationOptionsRequest
	{
		"username": "johndoe@example.com",
		"displayName": "John Doe",
		"authenticatorSelection": {
		"residentKey": false,
		"authenticatorAttachment": "cross-platform",
		"userVerification": "preferred"
		},
		"attestation": "direct"
	}

	Success Response:
	HTTP Status Code: 200 OK
	Body: application/json formatted ServerPublicKeyCredentialCreationOptionsResponse
	{
		"status": "ok",
		"errorMessage": "",
		"rp": {
			"name": "Example Corporation"
		},
		"user": {
			"id": "S3932ee31vKEC0JtJMIQ",
			"name": "johndoe@example.com",
			"displayName": "John Doe"
		},
		"challenge": "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN",
		"pubKeyCredParams": [
			{
				"type": "public-key",
				"alg": -7
			}
		],
		"timeout": 10000,
		"excludeCredentials": [
			{
				"type": "public-key",
				"id": "opQf1WmYAa5aupUKJIQp"
			}
		],
		"authenticatorSelection": {
			"residentKey": false,
			"authenticatorAttachment": "cross-platform",
			"userVerification": "preferred"
		},
		"attestation": "direct"
	}

	Error Response:
	HTTP Status Code: 4xx or 5xx
	Body: application/json formatted ServerResponse
	{
		"status": "failed",
		"errorMessage": "Missing challenge field!"
	}

</details>

<details>
<summary>API: 인증자 증명 응답</summary>

	Request:
	URL: /attestation/result
	Method: POST
	URL Params: None
	Body: application/json formatted ServerPublicKeyCredential with response field set to ServerAuthenticatorAttestationResponse
	{
		id: 'ADSUllKQmbqdGtpu4sjseh4cg2TxSvrbcHDTBsv4NSSX9...',
		rawId: ArrayBuffer(59),
		response: AuthenticatorAttestationResponse {
			clientDataJSON: ArrayBuffer(121),
			attestationObject: ArrayBuffer(306),
		},
		type: 'public-key'
	}

	Success Response:
	HTTP Status Code: 200 OK
	Body: application/json formatted ServerResponse
	{
		"status": "ok",
		"errorMessage": ""
	}

	Error Response:
	HTTP Status Code: 4xx or 5xx
	Body: application/json formatted ServerResponse
	{
		"status": "failed",
		"errorMessage": "Can not validate response signature!"
	}

</details>

<details>
<summary>IDL: ServerPublicKeyCredentialCreationOptionsRequest</summary>

	dictionary ServerPublicKeyCredentialCreationOptionsRequest {
		required DOMString username;
		required DOMString displayName;
		AuthenticatorSelectionCriteria authenticatorSelection;
		AttestationConveyancePreference attestation = "none";
	};

	required username - 사용자가 읽을 수 있는 엔티티 이름입니다.
	Ex) "alexm", "alex.p.mueller@example.com" or "+14255551234".

	required displayName - 표시 전용 사용자 계정에 대한 친숙한 이름입니다.
	Ex) "Alex P. Müller"

	authenticatorSelection - 인증자 관련 옵션을 추가적으로 설정하는 부분
	authenticatorAttachment: 사용자가 다른 클라이언트 장치에서 더 쉽게 재인증을 위해 플랫폼 자격 증명을 등록하는 데 사용할 수 있습니다. (cross-platform, platform)
	requireResidentKey: 기본값 false, true로 설정된 경우 공개 키 자격 증명을 만들 때 해당 공개키의 검증을 하도록 함.
	userVerification: 기본값 preferred
	required(작업에 대해 사용자 확인을 요구하며 응답에 UV 플래그가 설정되어 있지 않으면 작업에 실패함을 나타냅니다.)
	preferred(작업에 대해 사용자 확인을 선호하지만 응답에 UV 플래그가 설정되어 있지 않은 경우 작업에 실패하지 않음을 나타냅니다.)
	discouraged(작업 중에 사용자 검증이 사용되는 것을 원하지 않음을 나타냅니다.)

	attestation - 이 옵션을 사용하면 서버가 이 등록 이벤트에 대한 증명 데이터의 중요도를 나타낼 수 있습니다.
	값이 "none"이면 서버가 증명에 신경 쓰지 않음을 나타냅니다.
	"indirect" 값은 서버가 익명 증명 데이터를 허용함을 의미합니다.
	"direct"는 서버가 인증자로부터 증명 데이터를 수신하려는 것을 의미합니다.
	기본값은 "none"으로 설정됩니다.

</details>

<details>
<summary>IDL: ServerPublicKeyCredentialCreationOptionsResponse</summary>

	dictionary ServerPublicKeyCredentialCreationOptionsResponse : ServerResponse {
		required PublicKeyCredentialRpEntity rp;
		required ServerPublicKeyCredentialUserEntity user;

		required DOMString challenge;
		required sequence<PublicKeyCredentialParameters> pubKeyCredParams;

		unsigned long timeout;
		sequence<ServerPublicKeyCredentialDescriptor> excludeCredentials = [];
		AuthenticatorSelectionCriteria               authenticatorSelection;
		AttestationConveyancePreference              attestation = "none";
		AuthenticationExtensionsClientInputs         extensions;
	};

	required rp - PublicKeyCredentialRpEntity
	id: rpId에 대한 고유 식별자입니다.

	required user - ServerPublicKeyCredentialUserEntity
	id: base64url 인코딩된 id 버퍼
	displayName: 표시 전용 사용자 계정에 대한 친숙한 이름입니다.

	required challenge - 임의 base64url 인코딩 값(최소 16바이트 길이 및 최대 64바이트 길이)

	required pubKeyCredParams - PublicKeyCredentialParameters (공개 키 자격 증명 매개 변수 순서)
	type: 만들 자격 증명 유형을 지정합니다. 값은 PublicKeyCredentialType의 구성원이어야 하며, 알 수 없는 값을 무시하고 알 수 없는 유형의 매개 변수를 무시합니다.
	alg: 새로 생성된 자격 증명이 사용될 암호화 서명 알고리즘과 생성 될 비대칭 키 쌍의 유형을 지정합니다.

	timeout - 오류가 반환되기 전에 사용자가 등록 프롬프트에 응답해야 하는 시간(밀리초 단위).

	excludeCredentials - ServerPublicKeyCredentialDescriptor (자격증명의 중복 방지 및 자격증명에 도달하는 방법 여부와 결정)
	type: 만들 자격 증명 유형을 지정합니다. 값은 PublicKeyCredentialType의 구성원이어야 하며, 알 수 없는 값을 무시하고 알 수 없는 유형의 매개 변수를 무시합니다.
	id: 호출해서 참조하는 공개 키 자격 증명의 base64url 인코딩된 자격 증명 ID를 포함합니다.
	transports: 호출한 후, 공개 키 자격 증명의 관리 인증자와 통신할 수 있는 방법에 대한 힌트를 제공 ('usb', 'nfc' 등등)

	authenticatorSelection - 인증자 관련 옵션을 추가적으로 설정하는 부분
	authenticatorAttachment: 사용자가 다른 클라이언트 장치에서 더 쉽게 재인증을 위해 플랫폼 자격 증명을 등록하는 데 사용할 수 있습니다. (cross-platform, platform)
	requireResidentKey: 기본값 false, true로 설정된 경우 공개 키 자격 증명을 만들 때 해당 공개키의 검증을 하도록 함.
	userVerification: 기본값 preferred
	required(작업에 대해 사용자 확인을 요구하며 응답에 UV 플래그가 설정되어 있지 않으면 작업에 실패함을 나타냅니다.)
	preferred(작업에 대해 사용자 확인을 선호하지만 응답에 UV 플래그가 설정되어 있지 않은 경우 작업에 실패하지 않음을 나타냅니다.)
	discouraged(작업 중에 사용자 검증이 사용되는 것을 원하지 않음을 나타냅니다.)

	attestation - 이 옵션을 사용하면 서버가 이 등록 이벤트에 대한 증명 데이터의 중요도를 나타낼 수 있습니다.
	값이 "none"이면 서버가 증명에 신경 쓰지 않음을 나타냅니다.
	"indirect" 값은 서버가 익명 증명 데이터를 허용함을 의미합니다.
	"direct"는 서버가 인증자로부터 증명 데이터를 수신하려는 것을 의미합니다.
	기본값은 "none"으로 설정됩니다.

	extensions - 클라이언트 확장 입력 값

</details>

<details>
<summary>IDL: ServerAuthenticatorAttestationResponse</summary>

	dictionary ServerAuthenticatorAttestationResponse : ServerAuthenticatorResponse {
		required DOMString      clientDataJSON;
		required DOMString      attestationObject;
	};

	required clientDataJSON - base64url 인코딩된 clientDataJSON 버퍼
	// Parsing the clientDataJSON
	{
		challenge: "p5aV2uHXr0AOqUk7HQitvi-Ny1....",
		origin: "https://webauthn.guide",
		type: "webauthn.create"
	}

	challenge: 이것은 create() 호출에 전달된 것과 동일합니다. 서버는 반환된 challenge가 이 등록 이벤트에 대해 생성된 challenge와 일치하는지 확인해야 합니다.
	origin: 서버는 이 "origin" 문자열이 응용프로그램의 origin과 일치하는지 확인해야 합니다.
	type: 서버는 이 문자열이 실제로 "webauthn.create"인지 확인합니다. 다른 문자열이 제공되면 인증자가 잘못된 작업을 수행했음을 나타냅니다.

	required attestationObject - base64url 인코딩된 attestationObject 버퍼
	// Parsing the attestationObject
	{
		authData: Uint8Array(196),
		fmt: "fido-u2f",
		attStmt: {
			sig: Uint8Array(70),
			x5c: Array(1),
		},
	}

	authData: 인증자 데이터는 등록 이벤트에 대한 메타데이터와 향후 인증에 사용할 공개 키가 포함된 바이트 배열입니다.
	fmt: 증명 형식을 나타냅니다. 인증자는 여러 가지 방법으로 증명 데이터를 제공할 수 있습니다. 이는 서버가 증명 데이터를 구문 분석하고 검증하는 방법을 나타냅니다.
	attStmt: 이것은 증명문입니다. 이 개체는 표시된 증명 형식에 따라 다르게 나타납니다.
	이 경우 signature sig 및 증명 인증서 x5c가 제공됩니다.
	서버는 이 데이터를 사용하여 인증자로부터 받은 자격 증명 공개 키를 암호화하여 확인합니다.
	또한 서버는 인증서를 사용하여 취약한 것으로 추정되는 인증자를 거부할 수 있습니다.

	// Parsing the authenticator data (Parsing authData)
	{
		rpIdHash: "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVE",
		flags: {
			"value": 65,
			"up": true,
			"uv": false,
			"at": true,
			"ed": false
		},
		signCount: 0,
		attestedCredentialData: {
			aaguid: "AAAAAAAAAAAAAAAAAAAAAA",
			credentialId: "s83owuOGSCxZeyHsqHqF8oZM_F7kde53Pdnvzxhz9sQPK41SySk9JG0R8OIa1751SmNi37OX80oqIfewM9Azpg",
			credentialPublicKey: {
				kty: "EC",
				alg: "ES256",
				crv: "P-256",
				x: "qcmw3NcebCb_jrRtSKpD-FKpUuupsQW2LpljWpvig10",
				y: "b1QHO_NXteqUVdbGWwaAehQQ8E1rV8ZAgYiPTV6B5-o"
			}
		}
	}

	rpIdHash: 자격 증명의 범위가 지정되는 RP ID의 SHA-256 해시입니다.

	flags: 1byte로된 검증값
	Bit 0: User Present (UP) result.
	1은 유저가 존재한다.
	0은 유저가 존재하지 않는다.

	Bit 2: User Verified (UV) result.
	1은 유저가 검증되었다.
	0은 유저가 검증 되지 않았다.

	Bit 6: Attested credential data included (AT).
	인증자가 증명된 자격 증명 데이터를 추가했는지 여부를 나타냅니다.

	Bit 7: Extension data included (ED).
	인증자 데이터에 확장명이 있는지 여부를 나타냅니다.

	signCount: 서명 카운터, 32비트 부호 없는 빅 엔디언 정수.
	attestedCredentialData: 증명된 자격 증명 데이터(있는 경우)입니다. 이 길이는 인증되는 인증 정보 ID 및 인증 정보 공개 키의 길이에 따라 달라집니다.
	aaguid: 인증자의 AAGID입니다.
	credentialId: 인증 ID로 공개 키 자격 증명 소스 및 인증 확인을 식별하는 고유한 바이트 시퀀스입니다.

	credentialPublicKey: CTAP2 표준 CBOR 인코딩 양식을 사용하여 COSE_Key 형식으로 인코딩된 자격 증명 공개 키입니다.
	COSE_Key-encoded credential 공개 키는 "alg" 매개 변수를 포함해야 하며 다른 선택적 매개 변수를 포함할 수 없습니다.
	"alg" 매개 변수에는 COSE algorithmIdentifier 값이 포함되어야 합니다.
	인코딩된 자격 증명 공개 키에는 관련 키 유형 사양에서 규정한 추가 필수 매개 변수, 즉 키 유형 "kty" 및 알고리즘 "alg"에 필요한 매개 변수가 포함되어야 합니다.

</details>

<details>
<summary>FIDO Server 등록 알고리즘 자세히 보기</summary>

	1. Relying Party의 필요에 따라 PublicKeyCredentialCreationOptions를 설정해 옵션으로 지정합니다.

	2. navigator.credentials.create()를 호출하고 옵션을 공용 키 옵션으로 전달합니다. 성공적으로 해결된 약속의 결과가 자격 증명이 되도록 하십시오.
		1. 약속이 거부된 경우 사용자가 볼 수 있는 오류로 행사를 중단하거나 거부된 약속에서 사용할 수 있는 컨텍스트에서 결정될 수 있는 사용자 경험을 안내한다.
		2. 예를 들어 "InvalidStateError"와 같은 오류 코드로 약속이 거부되면 다른 인증자를 사용하도록 사용자에게 지시할 수 있습니다.

	3. 응답을 credential.response로 지정합니다.
		1. 응답이 AuthenticatorAttestationResponse의 인스턴스가 아닌 경우 사용자가 볼 수 있는 오류로 세리머니를 중단합니다.

	4. clientExtensionResults는 credential.getClientExtensionResults()를 호출한 결과입니다.

	5. JSONtext가 response.clientDataJSON 값에 대해 UTF-8 디코드를 실행한 결과라고 합니다.
		1. UTF-8 디코드 구현은 UTF-8 디코드 알고리즘에 의해 산출된 것과 동일한 결과를 산출하는 한 허용된다. 특히 선행 바이트 순서 표시(BOM)는 반드시 제거해야 합니다.

	6. 자격 증명을 생성하는 동안 수집된 클라이언트 데이터인 C를 JSON 텍스트에서 구현별 JSON 파서를 실행한 결과라고 합니다.
		1. C는 이 알고리즘에 의해 요구되는 C의 구성 요소가 참조 가능한 한 구현에 특화된 데이터 구조 표현일 수 있다.

	7. C.type의 값이 webauthn.create인지 확인합니다.

	8. C.challenge의 값이 options.challenge의 base64url 인코딩과 동일한지 확인합니다.

	9. C.origin의 값이 Related Party의 오리진과 일치하는지 확인합니다.

	10. C.tokenBinding.status의 값이 어설션을 얻은 TLS 연결의 토큰 바인딩 상태와 일치하는지 확인합니다. 해당 TLS 연결에 토큰 바인딩이 사용된 경우 C.tokenBinding.id이 연결에 대한 토큰 바인딩 ID의 base64url 인코딩과 일치하는지도 확인하십시오.

	11. response.clientDataJSON를 계산한 결과가 hash가 되도록 합니다. SHA-256을 사용합니다.

	12. AuthenticatorAttationResponse 구조의 destificationObject 필드에서 CBOR 디코딩을 수행하여 증명문 형식 ftt, 인증자 데이터 authData 및 증명문 atStmt를 가져옵니다.

	13. authData의 rpIdHash가 종속 당사자가 예상하는 RP ID의 SHA-256 해시인지 확인합니다.

	14. authData에서 플래그의 User Present 비트가 설정되어 있는지 확인합니다.

	15. 이 등록에 대해 사용자 확인이 필요한 경우 authData에 있는 플래그의 UserVerified 비트가 설정되어 있는지 확인합니다.

	16. authData의 자격 증명 공용 키의 "alg" 매개 변수가 options.pubKeyCredParams의 항목 중 하나의 alg 속성과 일치하는지 확인합니다.

	17. clientExtensionResults의 클라이언트 확장 출력 값과 authData의 확장에 있는 인증자 확장 출력 값이 options.extensions에서 제공된 클라이언트 확장 입력 값과 원치 않는 확장에 대한 관련 당사자의 특정 정책, 즉 options.extensions의 일부로 지정되지 않은 정책을 고려하여 예상대로인지 확인합니다. 일반적인 경우, "예상대로"의 의미는 의존 당사자에게만 해당되며 어떤 확장이 사용 중입니다.
		1. 클라이언트 플랫폼은 추가 인증자 확장 또는 클라이언트 확장을 설정하는 로컬 정책을 제정하여 원래 옵션의 일부로 지정되지 않은 인증자 확장 출력 또는 클라이언트 확장 출력에 값을 표시할 수 있습니다. Relying Parties는 이러한 상황을 처리할 준비가 되어 있어야 한다. 즉, 요청되지 않은 확장을 무시하든, 증명을 거부하든 말이다. Relying Party는 지역 정책과 사용 중인 확장에 따라 이 결정을 내릴 수 있습니다.
		2. 모든 확장은 클라이언트와 인증자 모두에게 선택 사항이기 때문에, Relying Party는 요청된 확장이 전혀 또는 일부만 작용한 경우를 처리할 준비를 해야 한다.

	18. 지원되는 WebAuthn 증명문 형식 식별자 값 집합에 대해 USASCII 대소문자 구분 일치를 수행하여 증명문 형식 결정. 등록된 WebAuthn 증명서 형식 식별자 값의 최신 목록은 [RFC8809]에 의해 설정된 IANA "WebAuthn 증명서 형식 식별자" 레지스트리 [IANA-WebAuthn-Registies]에 유지됩니다.

	19. attStmt, authData 및 해시가 주어진 증명문 형식 fmt의 검증 절차를 사용하여 attStmt가 유효한 증명 서명을 전달하는 올바른 증명문인지 확인하십시오.
		1. 각 증명문 형식은 자체 검증 절차를 지정합니다. 초기 정의된 형식에 대해서는 정의된 증명문 형식을, 최신 목록에 대해서는 [IANA-WebAuthn-Registries]를 참조하십시오.

	20. 검증에 성공한 경우 해당 증명 유형에 대해 허용되는 신뢰 앵커 목록(예: 증명 루트 인증서)과 신뢰할 수 있는 원본 또는 정책에서 증명문 형식을 가져옵니다. 예를 들어 FIDO Metadata Service(FIDO 메타데이터 서비스)는 authData에서 증명된 CredentialData의 aaid를 사용하여 이러한 정보를 얻을 수 있는 한 가지 방법을 제공합니다.

	21. 다음과 같이 19단계에서 검증 절차의 출력을 사용하여 증명 신뢰도를 평가합니다.
		1. 증명이 제공되지 않은 경우 종속 당사자 정책에서 증명이 허용되지 않는지 확인합니다.
		2. 자체 증명이 사용된 경우 종속 당사자 정책에서 자체 증명이 허용되는지 확인합니다.
		3. 그렇지 않으면 검증 절차로부터 증명 신뢰 경로로 반환된 X.509 인증서를 사용하여 증명 공개 키가 허용 가능한 루트 인증서까지 올바르게 연결되었는지 또는 그 자체가 허용 가능한 인증서인지 확인하십시오(즉, 단계 20에서 얻은 루트 인증서와 동일할 수 있음).

	22. credentialId가 아직 다른 사용자에게 등록되지 않았는지 확인합니다. 다른 사용자에게 이미 등록된 자격 증명에 대한 등록이 요청되는 경우, 종속 당사자는 이 등록에 실패하거나 이전 등록을 삭제하는 등의 방법으로 등록을 수락하기로 결정할 수 있습니다.

	23. atStmt 증명 문이 성공적으로 확인되고 신뢰할 수 있는 것으로 확인되면 options.user에 표시된 계정으로 새 자격 증명을 등록합니다.
		1. 종속 당사자 시스템에 적합한 경우 사용자 계정을 authData.attestedCredentialData의 credentialId 및 credentialPublicKey와 연결합니다.
		2. credentialId를 authData.signCount 값으로 초기화된 새 저장된 서명 카운터 값과 연결합니다. 또는 credentialId를 credential.response.getTransports()를 호출하여 반환되는 전송 힌트와 연결합니다. 이 값은 저장하기 전이나 후에 수정하면 안 됩니다. 클라이언트가 적합한 인증자를 찾는 방법을 알 수 있도록 이 값을 사용하여 향후 get() 호출에서 allowCredentials 옵션의 전송을 채우는 것이 좋습니다.

	24. 증명문 attStmt가 성공적으로 검증되었지만 위의 21단계에 따라 신뢰할 수없는 경우, Relying Party는 등록에 실패해야 합니다.
		1. 그러나 정책에 의해 허용되는 경우, 신뢰 당사자는 자격 증명 ID 및 자격 증명 공개 키를 등록할 수 있지만 자격 증명을 자체 증명이 있는 것으로 취급할 수 있습니다(6.5.3 증명 유형 참조). 그렇게하면, Relying Party는 공개 키 자격 증명이 특정 인증자 모델에 의해 생성되었다는 암호 증명이 없다고 주장합니다. 자세한 내용은 [FIDOsecRef] 및 [UAFProtocol]을 참조하십시오.

	증명 개체를 확인하려면 위 20단계에서 신뢰할 수 있는 신뢰 앵커를 결정하는 신뢰할 수 있는 방법이 있어야 합니다. 또한 인증서를 사용하는 경우, 종속 당사자는 중간 CA 인증서에 대한 인증서 상태 정보에 액세스할 수 있어야 합니다. 클라이언트가 증명 정보에 이 체인을 제공하지 않은 경우 종속 당사자도 증명 인증서 체인을 작성할 수 있어야 합니다.

</details>

## get flow

![Sequence diagrams](https://github.com/dc-choi/WebAuthn_study/blob/master/img/auth.png)

	이 절은 인증을 위해 서버와 교환된 메시지에 대한 개요로 시작한 후 메시지의 예를 보여 주며 메시지의 특정 IDL 정의로 끝납니다.
	WebAuthn에서 사용되는 용어 때문에 "인증"을 "인증서 받기", "인증 요청 받기" 또는 "인증 어설션 받기"로 부르기도 한다.

	등록에 대해 설명된 통신 흐름과 유사하게, 인증 흐름은 서버와 4개의 메시지를 교환해야 합니다.
	첫 번째 메시지 쌍은 클라이언트에서 서버로 보내는 ServerPublicKeyCredentialGetOptionsRequest 형식의 요청이며, 서버는 해당 ServerPublicKeyCredentialGetOptionsResponse를 클라이언트에 반환합니다.
	이 ServerPublicKeyCredentialGetOptionsResponse는 WebAuthn navigator.credentials.get() 호출에 대한 매개 변수로 사용됩니다.
	navigator.credentials.get()의 결과는 클라이언트가 응답 필드가 ServerAuthenticatorAssertionResponse로 설정된 ServerPublicKeyCredential로 포맷되어 서버로 전송됩니다.
	서버는 [WebAuthn] 규격의 섹션 7.2에 따라 어설션을 검증하고 해당 서버 응답을 반환합니다.

<details>
<summary>API: 자격 증명 가져오기 옵션</summary>

	Request:
	URL: /attestation/options
	Method: POST
	URL Params: None
	Body: application/json encoded ServerPublicKeyCredentialGetOptionsRequest
	{
		"username": "johndoe@example.com",
		"userVerification": "required"
	}

	Success Response:
	HTTP Status Code: 200 OK
	Body: applicaiton/json encoded ServerPublicKeyCredentialGetOptionsResponse
	{
		"status": "ok",
		"errorMessage": "",
		"challenge": "6283u0svT-YIF3pSolzkQHStwkJCaLKx",
		"timeout": 20000,
		"rpId": "https://example.com",
		"allowCredentials": [
			{
				"id": "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m",
				"type": "public-key"
			}
		],
		"userVerification": "required"
	}

	Error Response:
	HTTP Status Code: 4xx or 5xx
	Body: applicaiton/json encoded ServerResponse
	{
		"status": "failed",
		"errorMessage": "User does not exists!"
	}

</details>

<details>
<summary>API: 인증자 어설션 응답</summary>

	Request:
	URL: /assertion/result
	Method: POST
	URL Params: None
	Body: application/json encoded ServerPublicKeyCredential with response field set to ServerAuthenticatorAssertionResponse
	{
		"id":"LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
		"rawId":"LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
		"response":{
			"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
			"signature":"MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
			"userHandle":"",
			"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZ..."
		},
		"type":"public-key"
	}

	Success Response:
	HTTP status code: 200 OK
	Body: application/json encoded ServerResponse
	{
		"status": "ok",
		"errorMessage": ""
	}

	Error Response:
	HTTP status code: 4xx or 5xx
	Body: application/json encoded ServerResponse
	{
		"status": "failed",
		"errorMessage": "Can not validate response signature!"
	}

</details>

<details>
<summary>IDL: ServerPublicKeyCredentialGetOptionsRequest</summary>

	dictionary ServerPublicKeyCredentialGetOptionsRequest {
		required DOMString username;
		UserVerificationRequirement userVerification = "preferred";
	};

	required username - 사용자가 읽을 수 있는 엔티티 이름입니다.
	Ex) "alexm", "alex.p.mueller@example.com" or "+14255551234".

	userVerification: 기본값 preferred
	required(작업에 대해 사용자 확인을 요구하며 응답에 UV 플래그가 설정되어 있지 않으면 작업에 실패함을 나타냅니다.)
	preferred(작업에 대해 사용자 확인을 선호하지만 응답에 UV 플래그가 설정되어 있지 않은 경우 작업에 실패하지 않음을 나타냅니다.)
	discouraged(작업 중에 사용자 검증이 사용되는 것을 원하지 않음을 나타냅니다.)

</details>

<details>
<summary>IDL: ServerPublicKeyCredentialGetOptionsResponse</summary>

	dictionary ServerPublicKeyCredentialGetOptionsResponse : ServerResponse {
		required DOMString challenge;
		unsigned long timeout;
		USVString rpId;
		sequence<ServerPublicKeyCredentialDescriptor> allowCredentials = [];
		UserVerificationRequirement userVerification = "preferred";
		AuthenticationExtensionsClientInputs extensions;
	};

	required challenge - 임의 base64url 인코딩 값(최소 16바이트 길이 및 최대 64바이트 길이)

	timeout - 오류가 반환되기 전에 사용자가 등록 프롬프트에 응답해야 하는 시간(밀리초 단위).

	rpId - 생략할 경우 이 값은 원본 유효 도메인이 됩니다.

	allowCredentials - ServerPublicKeyCredentialDescriptor (자격증명의 중복 방지 및 자격증명에 도달하는 방법 여부와 결정)
	type: 만들 자격 증명 유형을 지정합니다. 값은 PublicKeyCredentialType의 구성원이어야 하며, 알 수 없는 값을 무시하고 알 수 없는 유형의 매개 변수를 무시합니다.
	id: 호출해서 참조하는 공개 키 자격 증명의 base64url 인코딩된 자격 증명 ID를 포함합니다.
	transports: 호출한 후, 공개 키 자격 증명의 관리 인증자와 통신할 수 있는 방법에 대한 힌트를 제공 ('usb', 'nfc' 등등)

	userVerification: 기본값 preferred
	required(작업에 대해 사용자 확인을 요구하며 응답에 UV 플래그가 설정되어 있지 않으면 작업에 실패함을 나타냅니다.)
	preferred(작업에 대해 사용자 확인을 선호하지만 응답에 UV 플래그가 설정되어 있지 않은 경우 작업에 실패하지 않음을 나타냅니다.)
	discouraged(작업 중에 사용자 검증이 사용되는 것을 원하지 않음을 나타냅니다.)

	extensions - 클라이언트 확장 입력 값

</details>

<details>
<summary>IDL: ServerAuthenticatorAssertionResponse</summary>

	dictionary ServerAuthenticatorAssertionResponse : ServerAuthenticatorResponse {
		required DOMString clientDataJSON;
		required DOMString authenticatorData;
		required DOMString signature;
		required DOMString userHandle;
	};

	required clientDataJSON - base64url 인코딩된 clientDataJSON 버퍼
	// Parsing the clientDataJSON
	{
		challenge: "p5aV2uHXr0AOqUk7HQitvi-Ny1....",
		origin: "https://webauthn.guide",
		type: "webauthn.get"
	}

	challenge: 이것은 get() 호출에 전달된 것과 동일합니다. 서버는 반환된 challenge가 이 등록 이벤트에 대해 생성된 challenge와 일치하는지 확인해야 합니다.
	origin: 서버는 이 "origin" 문자열이 응용프로그램의 origin과 일치하는지 확인해야 합니다.
	type: 서버는 이 문자열이 실제로 "webauthn.get"인지 확인합니다. 다른 문자열이 제공되면 인증자가 잘못된 작업을 수행했음을 나타냅니다.

	required authenticatorData- 등록 이벤트에 대한 메타데이터가 포함된 바이트 배열입니다. 등록 중에 수신된 authData와 유사하지만, 공용 키가 포함되지 않습니다.
	// Parsing the authenticator data (Parsing authenticatorData)
	{
		rpIdHash: "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVE",
		flags: {
			"value": 65,
			"up": true,
			"uv": false,
			"at": true,
			"ed": false
		},
		signCount: 0,
		attestedCredentialData: {
			aaguid: "AAAAAAAAAAAAAAAAAAAAAA",
			credentialId: "s83owuOGSCxZeyHsqHqF8oZM_F7kde53Pdnvzxhz9sQPK41SySk9JG0R8OIa1751SmNi37OX80oqIfewM9Azpg",
		}
	}

	rpIdHash: 자격 증명의 범위가 지정되는 RP ID의 SHA-256 해시입니다.

	flags: 1byte로된 검증값
	Bit 0: User Present (UP) result.
	1은 유저가 존재한다.
	0은 유저가 존재하지 않는다.

	Bit 2: User Verified (UV) result.
	1은 유저가 검증되었다.
	0은 유저가 검증 되지 않았다.

	Bit 6: Attested credential data included (AT).
	인증자가 증명된 자격 증명 데이터를 추가했는지 여부를 나타냅니다.

	Bit 7: Extension data included (ED).
	인증자 데이터에 확장명이 있는지 여부를 나타냅니다.

	signCount: 서명 카운터, 32비트 부호 없는 빅 엔디언 정수.
	attestedCredentialData: 증명된 자격 증명 데이터(있는 경우)입니다. 이 길이는 인증되는 인증 정보 ID 및 인증 정보 공개 키의 길이에 따라 달라집니다.
	aaguid: 인증자의 AAGID입니다.
	credentialId: 인증 ID로 공개 키 자격 증명 소스 및 인증 확인을 식별하는 고유한 바이트 시퀀스입니다.

	required signature - base64url 인코딩된 서명 버퍼
	이 자격 증명과 연결된 개인 키에 의해 생성된 서명입니다.
	서버에서 공개 키는 이 서명이 유효한지 확인하는 데 사용됩니다.

	required userHandle - ServerPublicKeyCredentialUserEntity
	id: base64url 인코딩된 id 버퍼이며, 등록 중에 제공된 user.id을 나타냅니다.

</details>

<details>
<summary>FIDO Server 인증 알고리즘 자세히 보기</summary>

	1. Relying Party의 필요에 따라 PublicKeyCredentialRequestOptions를 설정해 옵션으로 지정합니다.
		1. options.allowCredentials가 존재하는 경우, 각 항목의 전송 멤버는 해당 자격 증명이 등록되었을 때 credential.response.getTransports()에 의해 반환된 값으로 설정되어야 합니다.

	2. navigator.credentials.get() 및 pass 옵션을 publicKey 옵션으로 호출합니다. 자격 증명이 성공적으로 해결된 약속의 결과가 되도록 합니다. 약속이 거부된 경우, 사용자가 볼 수 있는 오류로 의식을 중단하거나 거부된 약속에서 사용 가능한 컨텍스트에서 결정할 수 있는 대로 사용자 경험을 안내하십시오. 서로 다른 오류 컨텍스트 및 그로 이어지는 상황에 대한 정보는 인증자 GetAssertion Operation을 참조하십시오.

	3. 응답을 credential.response로 지정합니다. 응답이 AuthenticatorAssertionResponse의 인스턴스가 아닌 경우 사용자가 볼 수 있는 오류로 세리머니를 중단합니다.

	4. clientExtensionResults는 credential.getClientExtensionResults()를 호출한 결과입니다.

	5. options.allowCredentials가 비어 있지 않으면 credential.id가 options.allowCredentials에 나열된 공개 키 자격 증명 중 하나를 식별하는지 확인하십시오.

	6. 인증할 사용자를 식별하고 이 사용자가 credential.id에서 식별한 공개 키 인증 정보 원본의 소유자인지 확인합니다.
		1. 예를 들어, 사용자 이름 또는 쿠키를 통해 인증식이 시작되기 전에 사용자가 식별된 경우, 식별된 사용자가 credentialSource의 소유자인지 확인합니다. response.userHandle이 있으면 userHandle을 해당 값으로 지정합니다. userHandle도 동일한 사용자에게 매핑되는지 확인합니다.
		2. 인증 방식을 시작하기 전에 사용자를 식별하지 못한 경우, response.userHandle이 있는지, 이 값으로 식별된 사용자가 credentialSource의 소유자인지 확인합니다.

	7. credential.id(또는 credential.rawId, base64url 인코딩이 사용 사례에 적합하지 않은 경우)을 사용하여 해당 자격 증명 공개 키를 찾아 credentialPublicKey를 해당 자격 증명 공개 키로 지정합니다.

	8. cData, authData 및 sign이 각각 응답의 clientDataJSON, authenticatorData 및 signature의 값을 나타내도록 합니다.

	9. JSONtext를 cData 값에 대해 UTF-8 디코드를 실행한 결과라고 합시다.
		1. UTF-8 디코딩의 구현은 UTF-8 디코딩 알고리즘에 의해 산출된 것과 동일한 결과를 산출하는 한 허용된다. 특히 선행 바이트 순서 표시(BOM)는 반드시 제거해야 합니다.

	10. 서명에 사용된 클라이언트 데이터인 C를 JSON 텍스트에서 구현별 JSON 파서를 실행한 결과라고 합니다.
		1. C는 이 알고리즘에 의해 요구되는 C의 구성 요소가 참조 가능한 한 구현에 특정한 데이터 구조 표현일 수 있다.

	11. C.type의 값이 webauthn.get 문자열인지 확인합니다.

	12. C.challenge의 값이 options.challenge의 base64url 인코딩과 동일한지 확인합니다.

	13. C.origin의 값이 Related Party의 오리진과 일치하는지 확인합니다.

	14. C.tokenBinding.status 값이 증명된 TLS 연결에 대한 토큰 바인딩 상태와 일치하는지 확인하십시오. 해당 TLS 연결에 토큰 바인딩이 사용된 경우 C.tokenBinding.id이 연결에 대한 토큰 바인딩 ID의 base64url 인코딩과 일치하는지도 확인하십시오.

	15. authData의 rpIdHash가 Relying Party가 예상하는 RP ID의 SHA-256 해시인지 확인합니다.
		1. appid 확장을 사용하는 경우이 단계에는 몇 가지 특별한 논리가 필요합니다. 자세한 내용은 10.1 FIDO AppID Extension (Appid)을 참조하십시오.

	16. authData에서 플래그의 User Present 비트가 설정되어 있는지 확인합니다.

	17. 이 어설션에 대해 사용자 확인이 필요한 경우 authData의 플래그 중 사용자 확인 비트가 설정되어 있는지 확인합니다.

	18. clientExtensionResults의 클라이언트 확장 출력 값과 authData의 확장에 있는 인증자 확장 출력 값이 options.extensions에서 제공된 클라이언트 확장 입력 값과 원치 않는 확장에 대한 관련 당사자의 특정 정책, 즉 options.extensions의 일부로 지정되지 않은 정책을 고려하여 예상대로인지 확인합니다. 일반적인 경우, "예상대로"의 의미는 의존 당사자에게만 해당되며 어떤 확장이 사용 중입니다.
		1. 클라이언트 플랫폼은 추가 인증자 확장 또는 클라이언트 확장을 설정하는 로컬 정책을 제정하여 원래 옵션의 일부로 지정되지 않은 인증자 확장 출력 또는 클라이언트 확장 출력에 값을 표시할 수 있습니다. Relying Parties는 이러한 상황을 처리할 준비가 되어 있어야 한다. 즉, 요청되지 않은 확장을 무시하든, 증명을 거부하든 말이다. Relying Party는 지역 정책과 사용 중인 확장에 따라 이 결정을 내릴 수 있습니다.
		2. 모든 확장은 클라이언트와 인증자 모두에게 선택 사항이기 때문에, Relying Party는 요청된 확장이 전혀 또는 일부만 작용한 경우를 처리할 준비를 해야 한다.

	19. SHA-256을 사용하여 cData에 대한 해시를 계산한 결과가 해쉬라고 하자.

	20. credential PublicKey를 사용하여 authData와 해시의 이진 연결에 대한 시그니처가 유효한지 확인합니다.
		1. 이 검증 단계는 FIDO U2F 인증자에 의해 생성된 서명과 호환된다.
		2. FIDO U2F Signature Format Compatibility 참조.

	21. storedSignCount를 credential.id과 연결된 저장된 시그니처 카운터 값으로 설정합니다. authData.signCount가 0이 아니거나 storedSignCount가 0이 아닌 경우 다음 하위 단계를 실행합니다.
		1. 만약 authdata.signcount가 저장된 SignCount보다 크다면 저장된 SignCount를 authData.signCount의 값으로 업데이트합니다.
		2. 만약 authdata.signcount가 저장된 SignCount보다 작거나 같다면 이는 인증자가 복제될 수 있다는 신호입니다. 즉, 자격 증명 개인 키의 복사본이 적어도 두 개 이상 존재하며 병렬로 사용되고 있습니다. Relying Party는 이 정보를 위험 평가 항목에 통합해야 합니다. 이 경우 Relying Party가 storedSignCount를 업데이트할지, 그렇지 않을지는 Relying Party에 따라 다릅니다.

	22. 위의 단계가 모두 성공한 경우, 적절한 인증 방식을 계속하십시오. 그렇지 않은 경우 인증에 실패하십시오.

</details>
