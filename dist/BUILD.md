# 재개3 배포 산출물

- 빌드 기준 main: `4a877d52771cdf9ad2b38121583c0b61bdf5e8c6`
- 빌드 환경: Go 1.24.5 darwin/amd64, `CGO_ENABLED=0 go build -trimpath`.
- 제품 소스 변경 없음. Darwin 바이너리는 **수집 미지원 stub**이다. 배포 파일 존재가 기능 성공 또는 사용자 경로 설치를 의미하지 않는다.
- 빌드 당시 기존 untracked Darwin 산출물 및 순차 재빌드 때문에 VCS metadata는 `vcs.modified=true`다. 소스 기준은 위 커밋이며 바이너리 식별은 아래 SHA256을 사용한다.
- `.test` 파일 두 개도 다시 빌드했으며 이전 파일과 해시가 같다.

| 파일 | SHA256 |
|---|---|
| portwho-linux-amd64 | 87d9f8f87e0208f56ebf1bad483980005324e36dd3cad2cb1ab21560dcd52fcd |
| portwho-linux-arm64 | c26531444999e6cf8235450aa9f918b091997e511fc2e9ad0d5e0783dd6bb997 |
| portwho-windows-amd64.exe | 17d74c4763d19967345c5aa5efe5ab156c690195e14f683452667580610ef9ab |
| portwho-darwin-amd64 | 43e554c134c54fd88344dcc409356ab6a3a9912e967cf9cc6864315986efde04 |
| portwho-darwin-arm64 | 35b70c291b0655e31fc8ecbf80c8a537bc72f1d1474b7ee9e8558f35863c4f97 |
| ports-linux-amd64.test | adb3f3cdafd61f5f73625747d530b78ad6fb750f111f6374b0feeb5b8c4d57ee |
| ports-windows-amd64.test.exe | b01f5c557582ef8cd7a0df2701160c63e1dd75c46d24230c73e2e11a438a9bd6 |
