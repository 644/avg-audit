# Arch Vulnerability Group auditor
avg-audit will check currently installed packages on Arch Linux based systems against https://security.archlinux.org/issues/. This is very similar to pacaudit and archsecure, however it allows for custom formatting of the fields and has all the same features (except the nagios plugin in pacaudit, which I plan to add). It has a couple of other minor improvements as well, such as testing against all known security vulnerabilities including fixed ones, which could be useful in case of outdated software. I also have other features in mind like running as a service, or alongside an update utility.

# Installation
`$ wget https://raw.githubusercontent.com/i34/avg-audit/master/avg-audit && chmod +x avg-audit`
```
Usage:
    -h    Show this help message
    -a    Show all fields
          This is equal to -f name,packages,status,severity,type,affected,fixed,ticket,issues
    -f    Custom format, e.g. -f packages,affected,severity
    -v    Show all vulnerable packages, not just ones on the system
    -c    Colorize output
    -t    Test against all packages, including fixed ones
    -l    Link to the full AVG URL
    -n    Do not count vulnerable/listed packages at the end

Fields:
    name        Link to the Arch Vulnerability Group number
    packages    List of the affected packages
    status      Shows whether it is fixed or not
    severity    From Critical, High, Medium, to Low
    type        Short description on the type of attack
    affected    Version number of the affected package
    fixed       Version number of the fixed package
    ticket      Ticket number for bugs.archlinux.org
    issues      List of related CVEs
```

# Example
![example.png](example.png)
