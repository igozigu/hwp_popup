# hwp_popup (`hwp_popup.exe` / `AsideHwpGuard`)

한컴오피스 한글(HWP/HWPX) COM 오토메이션(`HWPFrame.HwpObject`) 사용 시 발생하는 보안 승인 모달 창(`접근하려는 시도...`)을 **외부 런타임 의존성 없는 단일 실행 파일(`hwp_popup.exe`)** 하나로 영구 해결하는 **3중 방어(3-Layer Hybrid Defense)** 솔루션입니다.

---

## 핵심 아키텍처 (3-Layer Defense)

### Layer 1: 보안모듈 DLL 영구 배치 및 레지스트리 7종 전방위 등록 (사전 차단 1)
- 실행 파일 내부에 한컴 공식 `FilePathCheckerModuleExample.dll`을 리소스로 내장(Embedded Resource)하고 있어 단일 `.exe` 파일만으로 동작합니다.
- 실행 시 `%LocalAppData%\AsideHwpGuard\modules\FilePathCheckerModuleExample.dll`에 DLL을 추출 및 무결성(SHA-256) 검증합니다.
- `HKCU\Software\HNC\HwpAutomation\Modules` (및 `WOW6432Node`) 내 깨진 임시 경로(`Temp\_MEI*` 등)를 자동 복구하고, AI 에이전트 및 외부 도구가 사용하는 **7대 표준 모듈 키**를 일괄 등록합니다:
  - `FilePathCheckerModuleExample`
  - `FilePathCheckerModule`
  - `FilePathCheckDLL`
  - `FilePathCheckDLLModule`
  - `SecurityModule`
  - `Automation`
  - `AsideHwpSetup_v1`

### Layer 2: Aside 전역 지침(`AGENTS.md`) 비파괴 자동 패치 및 실시간 복구 (사전 차단 2)
- `%USERPROFILE%\.aside\u\*\AGENTS.md` 및 `%ASIDE_HOME%` 내 `AGENTS.md`를 스캔하여 기존 사용자 지침을 보존한 채 `<!-- ASIDE-HWP-GUARD:BEGIN -->` ~ `<!-- ASIDE-HWP-GUARD:END -->` 블록을 멱등성 있게 패치합니다.
- `FileSystemWatcher` 및 주기적 헬스체크를 통해 지침이 실수로 삭제되더라도 자동 복구합니다.

### Layer 3: 멀티 데스크톱 Win32 + WPF UIAutomation 실시간 팝업 자동 승인 가드 (최후 방어선)
- AI가 `RegisterModule` 호출을 누락한 스크립트를 실행하더라도, 백그라운드 데몬이 25ms 주기로 감지하여 `[모두 허용(N)]`(또는 `[접근 허용(Y)]`)을 즉시 무음 승인합니다.
- 구버전 한글 표준 대화상자(`#32770`)와 최신 한컴오피스 2022+ WPF 메시지박스(`HwndWrapper[hwp.exe;;...]` / `MessageBoxImpl`) 및 샌드박스 데스크톱(`Default` + `exebox-*`)을 모두 지원합니다.
- 승인 내역은 `%LocalAppData%\AsideHwpGuard\logs\guard.log`에 기록됩니다.

---

## 실행 및 CLI 옵션

```powershell
# 일반 설치 및 백그라운드 가드 실행 (트레이 아이콘 및 안내 표시)
.\hwp_popup.exe

# 무음 설치 및 백그라운드 가드 즉시 시작
.\hwp_popup.exe --silent

# 현재 설치 상태, DLL 해시, 레지스트리 7개 키, AGENTS.md, 데몬 동작 상태 진단
.\hwp_popup.exe --status

# 자체 E2E 검증 (Case 1: RegisterModule 호출 / Case 2: RegisterModule 누락 시 자동 클릭 검증)
.\hwp_popup.exe --test

# 데몬 종료, 시작프로그램 해제 및 AGENTS.md 마커 블록 제거
.\hwp_popup.exe --uninstall
```

---

## 빌드 방법

Windows 10/11 기본 내장 `.NET Framework 4.x` 컴파일러(`csc.exe`)를 사용하여 별도 SDK 설치 없이 즉시 빌드됩니다:

```powershell
.\build.ps1
```
