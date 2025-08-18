# PY-PID-ANALYZER Development Guide

## Project Overview
A Python utility for analyzing process IDs with specialized enhanced analysis for different application types (Java/Tomcat, web servers, databases, etc.).

**Platform Support**: Linux-only. This project exclusively targets Linux-based systems and will not support Windows or other non-Linux operating systems.

# Core development process requirements
- Always update applicable TODO.md, DEVELOPMENT_GUIDE.md, FUTURE_ROADMAP.md, HOWTO.md to reflect any modifications to the codebase
- All functionality must be implemented in a way consusive to future enhancements and interoprability with primary objectives
- No sensative data is permitted to be commited to this project
- If there is a need to supply sensative data, like access keys, credential, etc, it must be in a local env file that is never commited to the repo

# Project functionality requirements
- All operations to be performed by this set of utilities shall default to read only types.
- All operations that would be deamed not read only must appropreatly warn and/or prompt the user for approval
- The only way to allow non read only operations without warning or prompting must be controlled by a command line flag
- Project should minimize the usage of external dependencies whenever possible
- Project should favor usage of python standard libraries over external imported libraries

# Development workflow requirements
- Any future changes to project, either core functionality, requirements, syle, etc that would result in changes to core directives should prompt the developer with suggested updates to this ruleset