<p align="center"><img src="assets/course-image.png" width="160" alt="Docker Supply-Chain Security"></p>

# Docker Supply-Chain Security

Scan, pin, diff and gate what goes into an image.

Tested Rust code for the fourth course of the Docker specialization: pinscan finds base images that are not pinned by digest, diffs two SBOMs and fails a build that contains a denied component.

## Examples

| example | what it does |
|---|---|
| [`examples/pinscan`](examples/pinscan) | pins, diff and gate, each printing a contract line |

## Prerequisites

- Docker 25 or newer
- Rust 1.80 or newer
- A Linux or macOS terminal

---

<sub>Generated — do not edit by hand. Edit `course.toml` and re-render.</sub>
