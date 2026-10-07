# md5sum

개인 홈페이지 소스입니다. 빌드 도구 없이 HTML/CSS만으로 구성되어 GitHub Pages에서 바로 배포됩니다.

## 구성

| 파일 | 역할 |
|---|---|
| `index.html` | 페이지 본문 (소개 · 분야 · 프로젝트 · 연락처) |
| `assets/style.css` | 스타일 (라이트/다크 테마) |
| `.nojekyll` | Jekyll 처리 생략 |

## 수정 방법

`index.html`에서 `✏️` 주석이 달린 부분과 `[ ]` 안의 문구를 본인 정보로 바꾸면 됩니다.

## 배포 (GitHub Pages)

1. 저장소 **Settings → Pages** 이동
2. **Source**: `Deploy from a branch`, 브랜치와 `/ (root)` 선택 후 저장
3. 1~2분 후 `https://pol-md5sum.github.io/md5sum/` 에서 확인
