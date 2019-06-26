# Installation
`$ wget https://raw.githubusercontent.com/i34/archaudit/master/archaudit && chmod +x archaudit`
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

This is very similar to pacaudit and archsecure, however this allows for custom formatting of the fields and has all the same features (except the nagios plugin in pacaudit, which I plan to add). It has a couple of other minor improvements. I also have other features in mind like running as a service, or alongside an update utility.

# Example
![example.png](example.png)
