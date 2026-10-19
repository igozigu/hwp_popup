# [프로젝트 지시서] Aside 브라우저 한글(HWP) 보안 팝업 영구 해결 및 자동 승인 단일 실행 파일(`AsideHwpGuard.exe`) 개발

## 1. 배경 및 해결하려는 문제
Aside 브라우저(및 로컬 AI 에이전트)가 한컴오피스 한글(HWP)을 COM 오토메이션(`HWPFrame.HwpObject`)으로 제어하여 로컬 문서(`.hwp`, `.hwpx`)를 열거나 저장할 때마다 아래와 같은 한컴 보안 승인 모달 창이 발생하여 자동화 작업이 멈추는 문제가 있다.

- **창 제목:** `한글` 또는 `ᄒᆞᆫ글` (유니코드 옛한글 `U+1112 U+119E U+11AB U+AE00` 포함)
- **본문 메시지:** `<파일경로>\n한글을 이용하여 위 파일에 접근하려는 시도(파일의 손상 또는 유출의 위험 등)가 있습니다.\n정상적인 작업 과정에만 접근을 허용하십시오.`
- **버튼 구성:** `접근 허용(Y)`, `모두 허용(N)`, `허용 안 함(A)`, `모두 안 함(C)`

이 문제는 다음 3가지 원인으로 인해 재발한다:
1. **레지스트리 미등록 또는 임시 경로 깨짐:** `HKCU\Software\HNC\HwpAutomation\Modules`에 보안모듈 DLL이 등록되어 있지 않거나, PyInstaller 임시 폴더(`_MEI*`) 경로로 등록되어 재부팅 후 파일이 삭제된 경우
2. **`AGENTS.md` 지침 누락 또는 초기화:** 사용자가 Aside의 `AGENTS.md`를 수정하면서 한글 보안모듈 로드 지침이 사라진 경우
3. **AI 에이전트의 `RegisterModule` 호출 누락:** AI가 일회성 PowerShell/Python 스크립트를 작성할 때 `$h.SetMessageBoxMode(0x00020000)`만 호출하고, 정작 필수인 `$h.RegisterModule("FilePathCheckDLL", "모듈명")`을 빼먹고 `Open()`을 호출하는 경우

이 문제를 현재 PC뿐만 아니라 **다른 어떤 Windows 10/11 PC에서도 별도의 Python이나 추가 런타임 설치 없이 `.exe` 파일 하나만 실행하면 100% 해결**되도록 **3중 방어(3-Layer Hybrid) 구조의 단일 실행 파일(`AsideHwpGuard.exe`)**을 제작하라.

---

## 2. 기술 스택 및 빌드 제약사항 (필수 준수)
1. **언어 및 컴파일러:** Windows 10/11에 기본 내장된 **.NET Framework 4.x (`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`) 기반 C# + Win32 P/Invoke** (또는 외부 런타임 의존성이 전혀 없는 단일 네이티브 바이너리)를 사용하여, 타 PC에 `.exe` 파일 딱 하나만 복사해도 즉시 실행되게 하라.
2. **DLL 리소스 내장(Embedded Resource):**
   - 먼저 현재 PC(예: `%LocalAppData%\HwpAutomationSetup\modules\FilePathCheckerModuleExample.dll`, `%LocalAppData%\hwp2pdf\FilePathCheckerModuleExample.dll`, 또는 레지스트리/디스크 탐색)에서 한컴 공식 `FilePathCheckerModuleExample.dll`을 찾아 컴파일 시 `.exe` 내부의 Embedded Resource(`/resource`)로 포함시켜라.
   - 배포 시 `.dll` 파일을 따로 들고 다닐 필요 없이 `AsideHwpGuard.exe` 단일 파일(약 300KB 내외)로 동작해야 한다.
3. **Zero-Dependency & 저부하:** 백그라운드 상주 시 메모리 점유율 10MB 이하, 평소 CPU 점유율 0%를 유지해야 한다.

---

## 3. 핵심 아키텍처: 3중 방어(3-Layer Defense) 상세 구현 명세

### [Layer 1] 보안모듈 DLL 영구 배치 및 레지스트리 다중 키 전방위 등록 (사전 차단 1)
1. 실행 시 내장된 `FilePathCheckerModuleExample.dll`을 영구 경로인 `%LocalAppData%\AsideHwpGuard\modules\FilePathCheckerModuleExample.dll`에 추출한다(이미 존재하고 SHA-256 해시가 일치하면 건너뜀).
2. 레지스트리 `HKCU\Software\HNC\HwpAutomation\Modules` (및 `HKCU\Software\WOW6432Node\HNC\HwpAutomation\Modules`)를 열어 다음 작업을 수행한다:
   - 기존 등록된 값 중 대상 파일이 실제로 존재하지 않는 깨진 항목(예: `Temp\_MEI*` 등)을 모두 정상 영구 DLL 경로로 교정한다.
   - AI 모델(GPT, Claude, Gemini)과 외부 도구들이 학습 데이터상 습관적으로 호출하는 **아래 7개 표준 키 이름 모두**를 위 영구 DLL 절대경로(`REG_SZ`)로 일괄 등록한다:
     - `FilePathCheckerModuleExample`
     - `FilePathCheckerModule`
     - `FilePathCheckDLL`
     - `FilePathCheckDLLModule`
     - `SecurityModule`
     - `Automation`
     - `AsideHwpSetup_v1`

### [Layer 2] Aside 전역 지침(`AGENTS.md`) 비파괴 자동 패치 및 자동 복구 (사전 차단 2)
1. `%USERPROFILE%\.aside\u\*\AGENTS.md` (및 `%ASIDE_HOME%` 환경변수 경로)를 모두 스캔한다.
2. 기존 `AGENTS.md`의 사용자 지침은 **절대 덮어쓰거나 훼손하지 말고**(UTF-8 인코딩 유지), 아래 마커 블록(`<!-- ASIDE-HWP-GUARD:BEGIN -->` ~ `<!-- ASIDE-HWP-GUARD:END -->`)이 없을 때만 파일 끝에 추가하고, 이미 있으면 최신 내용으로 갱신(멱등성 보장)한다:
   ```markdown
   <!-- ASIDE-HWP-GUARD:BEGIN -->
   ## [필수] 한글(HWP/HWPX) COM 자동화 보안모듈 초기화 규칙
   - PowerShell 또는 Python 등에서 `HWPFrame.HwpObject` COM 객체를 생성할 때는 `Open`, `SaveAs`, `Insert` 등 파일 접근 메서드를 호출하기 **직전 첫 줄에 반드시 보안모듈 등록 코드**를 포함해야 한다 (`SetMessageBoxMode`만으로는 보안 승인창이 차단되지 않음).
   - **PowerShell 필수 패턴:**
     ```powershell
     $h = New-Object -ComObject HWPFrame.HwpObject
     [void]$h.RegisterModule("FilePathCheckDLL", "FilePathCheckerModule")
     [void]$h.SetMessageBoxMode(0x00020000)
     ```
   - **Python 필수 패턴:**
     ```python
     hwp = win32com.client.Dispatch("HWPFrame.HwpObject")
     hwp.RegisterModule("FilePathCheckDLL", "FilePathCheckerModule")
     hwp.SetMessageBoxMode(0x00020000)
     ```
   <!-- ASIDE-HWP-GUARD:END -->
   ```
3. 백그라운드 데몬이 동작하는 동안 사용자가 `AGENTS.md`를 편집하여 위 블록이 실수로 삭제되더라도, 주기적 검사(예: 60초 간격 또는 `FileSystemWatcher`)를 통해 누락 시 자동으로 다시 패치되도록 구현한다.

### [Layer 3] Win32 백그라운드 보안 팝업 자동 승인 가드 (사후 즉시 해결 - 최후 방어선)
AI가 긴 대화 중 지침을 잊고 `RegisterModule`을 누락한 스크립트를 실행하더라도, 사용자 화면에서 작업이 멈추지 않도록 백그라운드에서 즉시 `[모두 허용(N)]`을 눌러주는 Watchdog을 구현한다.
1. **정밀 타겟팅 조건 (오작동 방지 필수):**
   일반적인 한글 저장 확인창("저장하시겠습니까?") 등을 잘못 누르지 않도록 아래 **3가지 조건을 모두 만족하는 창**만 타겟팅한다.
   - **조건 A (창 클래스 및 프로세스/타이틀):** 최상위 윈도우 클래스명이 `#32770`(표준 대화상자)이고, 소유 프로세스가 `Hwp.exe`이거나 창 제목에 `한글` 또는 `ᄒᆞᆫ글`(`\u1112\u119E\u11AB\uAE00`)이 포함됨.
   - **조건 B (본문 경고 문구 일치):** 자식 컨트롤(`Static` 텍스트 등)의 텍스트를 `EnumChildWindows` + `GetWindowText`로 스캔했을 때 `"접근하려는 시도"` 또는 `"파일의 손상 또는 유출의 위험"` 또는 `"정상적인 작업 과정에만 접근을 허용"` 문구가 존재함.
   - **조건 C (대상 버튼 존재):** 자식 `Button` 컨트롤 중 텍스트가 `"모두 허용"`(`모두 허용(N)`, `모두 허용(&N)`) 또는 `"접근 허용"`(`접근 허용(Y)`, `접근 허용(&Y)`)인 버튼이 존재함.
2. **즉시 자동 승인 액션 (50ms 이내):**
   - 감지 즉시 **`"모두 허용(N)"` 버튼을 최우선**으로 선택(없을 경우 `"접근 허용(Y)"`)하여 Win32 `SendMessage(hButton, BM_CLICK, 0, 0)` (및 필요 시 부모 창에 `WM_COMMAND` 전송)을 실행해 포커스를 빼앗지 않고 무음으로 승인 처리한다.
   - 승인 처리 시 `%LocalAppData%\AsideHwpGuard\logs\guard.log`에 타임스탬프와 승인 처리 사실을 1줄 로그로 기록한다.

---

## 4. 설치/실행 UX 및 CLI 인터페이스
1. **단일 인스턴스 보장:** `Global\AsideHwpGuard_Mutex`를 사용하여 중복 실행을 방지한다.
2. **일반 실행 (더블클릭 / 인자 없음 또는 `--install`):**
   - 현재 실행 파일이 `%LocalAppData%\AsideHwpGuard\AsideHwpGuard.exe`가 아니면 해당 경로로 자기 자신을 복사한다.
   - Layer 1(DLL 추출 + 레지스트리 7종 등록 + 깨진 경로 복구) 및 Layer 2(`AGENTS.md` 패치)를 즉시 수행한다.
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`에 `"AsideHwpGuard"` 이름으로 `"<설치경로>\AsideHwpGuard.exe" --background`를 등록하여 윈도우 시작 시 자동 실행되게 한다.
   - 시스템 트레이 아이콘(`NotifyIcon`)을 표시하고 백그라운드 감시(Layer 3) 모드로 진입한다.
   - 트레이 우클릭 메뉴 제공:
     - `[상태 진단 및 즉시 복구]`
     - `[로그 폴더 열기]`
     - `[자동 시작 해제 및 제거(Uninstall)]`
     - `[종료]`
   - 최초 설치 실행 시 트레이 풍선 알림(BalloonTip) 또는 간단한 안내창으로 `"Aside 한글 보안 팝업 해결 및 자동 가드가 활성화되었습니다."`를 알린다 (`--background`나 `--silent` 실행 시에는 알림 생략).
3. **CLI 옵션 지원:**
   - `--background` / `--silent`: UI 알림 없이 즉시 Layer 1·2 점검 후 트레이 백그라운드 감시 시작
   - `--status`: 현재 DLL 해시, 레지스트리 7개 키 상태, `AGENTS.md` 패치 여부, 백그라운드 프로세스 실행 여부를 진단하여 출력
   - `--test`: 자체 E2E 검증 모드 실행 (아래 5번 항목 참조)
   - `--uninstall`: 실행 중인 데몬 종료, 시작프로그램 레지스트리 제거, `AGENTS.md` 내 마커 블록 제거

---

## 5. 빌드 후 필수 자체 검증 (End-to-End Test)
코드를 작성하고 `AsideHwpGuard.exe`를 컴파일한 뒤, 에이전트는 반드시 다음 검증을 직접 수행하고 결과를 보고하라:
1. `AsideHwpGuard.exe --silent`를 실행하여 설치, 레지스트리 7종 등록, `AGENTS.md` 패치, 백그라운드 데몬 기동을 완료한다.
2. **Test Case 1 (`RegisterModule` 정상 동작 검증):**
   PowerShell에서 `New-Object -ComObject HWPFrame.HwpObject` 생성 후 `$h.RegisterModule("FilePathCheckDLL", "FilePathCheckerModule")`을 호출하고 임시 `.hwp` 파일을 저장/열기했을 때 팝업 없이 즉시 통과하는지 확인한다.
3. **Test Case 2 (`RegisterModule` 누락 시 Layer 3 Auto-Clicker 동작 검증):**
   일부러 `RegisterModule`을 호출하지 않은 새 `HWPFrame.HwpObject` 인스턴스에서 임시 `.hwp` 파일에 대해 `$h.Open()`을 호출했을 때, 백그라운드 데몬(`AsideHwpGuard.exe`)이 보안 팝업을 자동으로 감지하여 `[모두 허용(N)]`을 클릭하고 `Open()`이 멈추지 않고 `True`를 반환하는지 검증한다 (`guard.log` 기록 확인 포함).