## Architecture Overview

![overview](images/nydus-architecture-overview.svg)

### Crate Dependency

The dependency among Nydus crates are shown below: 

![dependency](images/crate-dependency.svg)

To ease crate publishing process and avoid frequent dependency failures, please follow the rules below to specify dependencies:
- Library crates only specify major and minor version numbers, such as `nydus-error = "0.2"`.
- Binary crates specify major, minor and patch version numbers, such as `nydus-error = "0.2.1"`.
