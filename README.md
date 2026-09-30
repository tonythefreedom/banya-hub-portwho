# banya-hub-portwho

banya 에이전트 허브 협업 시나리오의 산출물입니다. 감독·리서치·앱·테스트 봇이
서로 다른 물리 머신(macOS·Windows/WSL·Linux arm64)에서 메시지로 협업해 만드는
순수 Go(cgo 없음) 크로스 플랫폼을 목표로 하는 `portwho` CLI — 현재 Linux 구현으로,
외부 명령 없이 열린 포트와 그것을 쥔 프로세스를 보여 준다.

- 앱 봇은 여기서 코드를 만들고 패치(git format-patch)를 감독 봇에게 보냅니다.
- 감독 봇만 이 레포에 푸시합니다 (키는 감독 봇에만 있습니다).
- 빌드·테스트·설치 봇들은 이 레포를 clone 해 각자의 OS 에서 빌드하고 검증합니다.

## Linux 1단계

Go 1.24 이상, 외부 의존성 없이 빌드합니다. 실행 중 외부 명령을 호출하지 않습니다.

```sh
CGO_ENABLED=0 go build -o bin/portwho ./cmd/portwho
./bin/portwho
./bin/portwho --all --devices --json
CGO_ENABLED=0 go test ./...
CGO_ENABLED=1 GOMAXPROCS=20 go test -race ./...
GOMAXPROCS=20 go test ./internal/ports -run '^$' -fuzz FuzzProcTable -fuzztime=30s -parallel=20
PORTWHO_TEST_DEVICES=1 go test ./internal/ports -run TestDeviceSelf -v
```

- 기본값: TCP LISTEN과 모든 UDP 소켓. `--all`은 TCP의 다른 상태도 포함합니다.
- `--json`: sockets/devices/warnings/scope 구조. 소유자 없는 소켓도 `owners: []`로 보존합니다.
- `--devices`: `/dev/nvidia*`, `/dev/dxg` 경로를 연 프로세스 목록을 추가합니다.
  GPU 연산 사용률이나 장치 접근 가능 여부를 나타내지는 않습니다. FD 대상의 문자 장치
  유형을 확인합니다. 다른 경로의 별칭/rdev 기반 재매핑은 지원하지 않습니다.
- Linux `/proc/net/{tcp,tcp6,udp,udp6}`는 **현재 네트워크 네임스페이스**에 한정됩니다.
  `/proc/<pid>/fd` inode로 모든 보이는 소유자를 연결하며 PID별 중복 FD는 합칩니다.
  IPv6 link-local의 zone/interface는 해당 테이블에서 복원하지 못하므로 표시하지 않습니다.
- 권한, hidepid, 프로세스 종료, PID 재사용, 다른 네임스페이스 때문에 소유자나
  메타데이터가 누락될 수 있습니다. 전체 스냅샷은 원자적이지 않습니다. 경고를 확인하십시오.
- 빈 문자열/표의 `?`는 알 수 없음입니다. socket UID와 process **real UID**는 별도입니다.
  사용자명은 `/etc/passwd`로만 조회하며 NSS/LDAP는 지원하지 않습니다. 숫자 UID는 보존합니다.
- `comm` 이름은 커널에서 잘릴 수 있고 exe 경로는 프로세스 mount namespace 기준입니다.
  ` (deleted)` 표기를 보존합니다. 컨테이너 표시는 cgroup 마커 휴리스틱이며,
  마커가 없거나 cgroup이 `/`라고 호스트 프로세스로 단정하지 않습니다.
- macOS/Windows 및 기타 OS는 현재 명시적 미지원 오류 stub입니다. 크로스 빌드 성공은
  해당 OS의 포트 수집 구현/실행 검증을 의미하지 않습니다.
- 모든 파일 fixture는 테스트가 생성한 합성 데이터입니다. self TCP/UDP IPv4·IPv6
  통합 테스트는 실제 소켓을 엽니다(IPv6 불가 시 해당 하위 테스트 skip).
  실제 장치 테스트는 opt-in이며 읽기 전용 open을 수행하고 ioctl/장치 쓰기는 하지 않습니다.
- race 검사는 Go race runtime 때문에 `CGO_ENABLED=1`과 C toolchain이 필요하지만,
  제품 코드에는 cgo 사용이 없고 배포 바이너리는 `CGO_ENABLED=0`으로 빌드합니다.

작업 폴더 밖의 캐시/임시 파일 쓰기를 피하려면 먼저 `.cache/{tmp,go-build,go-mod}`를 만들고
`TMPDIR`, `GOTMPDIR`를 `$PWD/.cache/tmp`, `GOCACHE`를 `$PWD/.cache/go-build`,
`GOPATH`를 `$PWD/.cache/go-mod`로 지정합니다.
