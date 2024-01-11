# Introduction

DevSecOps Security Tools

# Defect Dojo

[Architecture And Usage Example](defect_dojo/README.md)

# Utils

[Domain Language Transformation And Use of Logger](utils/README.md)

# Objective

# Project layout

```
NU0429001_devsecops_engine
├───.github
│   └───workflows
│           engine_core.yaml         -> CD pipeline for the engine core.
│           engine_sast.yaml         -> CD pipeline for the engine sast.
│           engine_dast.yaml         -> CD pipeline for the engine dast.
│           engine_sca.yaml         -> CD pipeline for the engine sca.
│           engine_utilities.yaml         -> CD pipeline for the engine utilities.
|
├───engine_core -> Code and Docker file for the engine_core.
|           test
|           src
|               applications
|               deploment
|               domain
|                   model
|                   usecases
|               infraestructure
|                   driven_adapters
|                   entry_points
|                   utils
```

# How can I help?
