# hwp_popup (`hwp_popup.exe` / `AsideHwpGuard`)

한글(HWP/HWPX) COM 자동화의 보안 승인창을 처리하는 단일 실행 파일입니다. DLL, 레지스트리 등록, Aside 지침, 팝업 감시를 사용자 계정별로 관리합니다.

## 보안모듈 등록과 다른 프로그램의 공존

`1.1.0`부터 각 프로그램이 소유하는 등록명을 분리합니다.

| 등록명 | hwp_popup 처리 |
|---|---|
| `AsideHwpGuard_FilePathChecker_v1` | 전용 등록. 누락·잘못된 경로·자료형을 설치 및 주기 점검 때 복구 |
| `FilePathCheckerModuleExample`, `FilePathCheckerModule`, `FilePathCheckDLL`, `FilePathCheckDLLModule`, `SecurityModule`, `Automation` | 값이 아예 없을 때만 호환용으로 생성. 기존 값은 경로·자료형과 관계없이 보존 |
| `AsideHwpSetup_v1`, `AutoPdf_FilePathChecker_v1` 및 나머지 모든 타 도구 등록 | 생성·변경·삭제하지 않음 |

- `%LocalAppData%\AsideHwpGuard\modules\FilePathCheckerModuleExample.dll`에 내장 DLL을 추출하고 SHA-256을 검증합니다. 추출에 실패하면 등록을 진행하지 않습니다.
- `HKCU\Software\HNC\HwpAutomation\Modules`와 `HKCU\Software\WOW6432Node\HNC\HwpAutomation\Modules`에 같은 소유권 정책을 적용합니다.
- 다른 프로그램의 DLL이 이동하거나 삭제되어도 그 등록을 가로채지 않습니다. 해당 프로그램의 설치·복구 기능으로 고쳐야 합니다.
- 다른 PC에서는 새 실행 파일을 각 Windows 사용자 계정으로 실행합니다. DLL과 등록 경로는 해당 PC의 `%LocalAppData%`에서 생성하므로 이전 PC의 절대 경로를 복사할 필요가 없습니다.
- auto_pdf도 전용 `AutoPdf_FilePathChecker_v1`을 쓰는 버전으로 업데이트해야 합니다. 구버전 hwp_popup 데몬이 실행 중인 PC에는 새 hwp_popup도 설치해야 합니다.

새 자동화 코드는 전용 등록명을 사용합니다.

```powershell
$h = New-Object -ComObject HWPFrame.HwpObject
[void]$h.RegisterModule("FilePathCheckDLL", "AsideHwpGuard_FilePathChecker_v1")
[void]$h.SetMessageBoxMode(0x00020000)
```

```python
hwp = win32com.client.Dispatch("HWPFrame.HwpObject")
hwp.RegisterModule("FilePathCheckDLL", "AsideHwpGuard_FilePathChecker_v1")
hwp.SetMessageBoxMode(0x00020000)
```

## 지침과 팝업 감시

- `%USERPROFILE%\.aside\u\*\AGENTS.md` 및 `%ASIDE_HOME%`의 관리 마커 블록을 갱신합니다. 블록 밖의 기존 지침은 보존합니다. 생성하는 코드 예제도 전용 등록명을 사용합니다.
- Win32 및 WPF 한글 보안 대화상자를 감시하고 자동 승인합니다. 기존 `Default`, `exebox-*` 데스크톱 지원은 유지합니다.
- `AutoPdf-`로 시작하는 전용 데스크톱은 열거나 창을 검사하지 않습니다. auto_pdf의 격리 변환과 보안모듈 검증이 외부 자동 클릭의 영향을 받지 않도록 합니다.
- 로그: `%LocalAppData%\AsideHwpGuard\logs\guard.log`.

## 설치와 업데이트

```powershell
.\hwp_popup.exe            # 설치 및 가드 시작
.\hwp_popup.exe --silent   # 무음 설치 및 가드 시작
.\hwp_popup.exe --status   # 두 등록 경로, 소유/보존 정책, DLL 해시, 실행 상태 진단
.\hwp_popup.exe --uninstall
```

업데이트할 때 설치 경로의 두 실행 파일이 새 빌드와 다르면, 정확히 해당 설치 경로에서 `--daemon` 또는 `--daemon-notify`로 실행 중인 가드만 종료한 뒤 교체합니다. 두 복사본의 SHA-256 일치와 데몬 시작을 확인해야 설치가 성공합니다. 잠긴 파일 교체를 무시한 채 구버전 데몬을 남기지 않습니다. 설치 경로 밖의 알 수 없는 가드가 실행 중이면 설치를 실패로 표시하므로 그 가드를 종료하고 다시 실행하십시오. 이 업데이트 절차는 한글 프로세스를 종료하지 않습니다.

제거 시 자동 시작과 지침의 관리 블록을 해제합니다. 기존 DLL과 모듈 등록은 다른 자동화의 참조를 보존하기 위해 남겨 둡니다.

## 빌드와 검증

Windows 기본 `.NET Framework 4.x` 컴파일러를 사용합니다.

```powershell
.\build.ps1
.\test.ps1
```

`test.ps1`은 임의의 테스트용 HKCU 분기와 임시 파일만 사용합니다. 32/64비트 레지스트리 보기에서 신규 설치, 정상·손상된 외부 등록 보존, 전용 등록 복구, 경로 이동, 반복 복구, DLL 누락, 데스크톱 제외, 업데이트 대상 식별을 검증합니다. 테스트 후 해당 분기와 임시 파일을 정리하며 한글 COM·설치·실행 중인 데몬은 건드리지 않습니다.

기존 `hwp_popup.exe --test`는 COM과 팝업 자동 승인을 시험하는 수동 E2E 기능입니다. **실행 전후 모든 Hwp 프로세스를 종료하므로, 저장되지 않은 문서가 있는 PC에서는 실행하지 마십시오.** 회귀 검증에는 위의 안전한 `test.ps1`을 사용합니다.