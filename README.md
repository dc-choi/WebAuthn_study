# WebAuthn_study

## create flow

![Sequence diagrams](https://github.com/dc-choi/WebAuthn_study/blob/master/img/reg.png)

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

## get flow

![Sequence diagrams](https://github.com/dc-choi/WebAuthn_study/blob/master/img/auth.png)

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