# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]
### Added
- Added support to specify the vulnerability criticality
- Added support to pull fixed state vulnerabilities and update fixed vulnerabilities within SecurityHub.

### Changed
- By default, we will only ingest critical vulnerabilities.

## [0.1.0] - 2019-01-18
### Added
- Ability to re-run every X hours and only import delta.
- Command-line argument handling
- Environment Variables correlating to parameterized args.
- Dockerfile for building dockerized versions of the script.
- Requirements file for management of required packages.

### Changed
- Complete rewrite of the code to follow PEP8 and python conventions.


## [0.0.1] - 2018-11-20
### Added
- Initial version