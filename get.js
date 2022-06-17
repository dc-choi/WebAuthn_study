const publicKeyCredentialRequestOptions = { // 서버에 의해 지정된 여러 개의 필수 및 선택 필드가 포함되어 있습니다.
    challenge: Uint8Array.from(randomStringFromServer, c => c.charCodeAt(0)),
	// 서버에서 생성된 암호화 랜덤 바이트여야 합니다.
    allowCredentials: [{
        id: Uint8Array.from(credentialId, c => c.charCodeAt(0)),
        type: 'public-key',
        transports: ['usb', 'ble', 'nfc'],
    }],
	/**
	 * 서버가 사용자가 인증할 자격 증명을 브라우저에 알려줍니다.
	 * 등록하는 동안 검색되고 저장된 credentialId가 여기에 전달됩니다.
	 * 서버는 선택적으로 USB, NFC 및 Bluetooth와 같이 선호하는 전송을 나타낼 수 있습니다.
	 */
    timeout: 60000,
	// 사용자가 인증 확인 메시지에 응답해야 하는 시간(밀리초)을 선택적으로 나타냅니다.
}

const assertion = await navigator.credentials.get({ // 서명이 포함된 등록 중에 생성된 자격 증명 검색 요청
    publicKey: publicKeyCredentialRequestOptions
});

console.log(assertion); // PublicKeyCredential

{
    id: 'ADSUllKQmbqdGtpu4sjseh4cg2TxSvrbcHDTBsv4NSSX9...',
	// 인증 어설션을 생성하는 데 사용된 인증 정보의 식별자입니다.
    rawId: ArrayBuffer(59),
	// 바이너리 형식으로 된 식별자입니다.
    response: AuthenticatorAssertionResponse {
        authenticatorData: ArrayBuffer(191),
		/**
		 * 인증자 데이터는 등록 중에 수신된 authData와 유사하지만,
		 * 여기에는 공용 키가 포함되지 않는다는 점이 눈에 띕니다.
		 * 이것은 어설션 서명을 생성하기 위해 소스 바이트로 인증하는 동안 사용되는 또 다른 항목입니다.
		 */
        clientDataJSON: ArrayBuffer(118),
		/**
		 * clientDataJSON은 브라우저에서 인증자로 전달된 데이터의 모음입니다.
		 * 이것은 서명을 생성하기 위해 소스 바이트로 인증 중에 사용되는 항목 중 하나입니다.
		 */
        signature: ArrayBuffer(70),
		/**
		 * 이 자격 증명과 연결된 개인 키에 의해 생성된 서명입니다.
		 * 서버에서 공개 키는 이 서명이 유효한지 확인하는 데 사용됩니다.
		 */
        userHandle: ArrayBuffer(10),
		/**
		 * 이 필드는 인증자가 선택적으로 제공하며, 등록 중에 제공된 user.id을 나타냅니다.
		 * 서버의 사용자와 이 주장을 연결하는 데 사용할 수 있습니다.
		 * UTF-8 바이트 배열로 인코딩되어 있습니다.
		 */
    },
    type: 'public-key'
}

/**
 * 인증 데이터 분석 및 검증
 * 어설션을 획득한 후에는 유효성 검사를 위해 서버로 전송됩니다.
 * 인증 데이터가 완전히 확인되면 등록 중에 데이터베이스에 저장된 공용 키를 사용하여 서명이 확인됩니다.
 */

// 예: 서버에서 어설션 서명 확인(의사 코드)
const storedCredential = await getCredentialFromDatabase(userHandle, credentialId);
const signedData = (authenticatorDataBytes + hashedClientDataJSON);
const signatureIsValid = storedCredential.publicKey.verify(signature, signedData);

/**
 * 확인은 서버에서 사용되는 언어 및 암호화 라이브러리에 따라 다르게 나타납니다. 그러나 일반적인 절차는 동일합니다.
 * 서버가 사용자와 연결된 공용 키 개체를 검색합니다.
 * 서버는 공용 키를 사용하여 서명을 확인합니다.
 * 이 키는 authenticatorData바이트와 clientDataJSON의 SHA-256 해시를 사용하여 생성됩니다.
 */

if (signatureIsValid) {
    return "Hooray! User is authenticated! 🎉";
} else {
    return "Verification failed. 😭"
}