# checkpoint-builk-import-to-group
builk import ip address list from file to checkpoint r80.X and add to new or existing group
# usage:
### python .\api.py --user 'username' --ip 'management ip --cmd 'set-group' --file 'file path' --grp_name 'group name'
### python .\api.py --user test --ip 1.1.1.1 --cmd 'set-group' --file .\bad_ip_list.csv --grp_name 'bad_ips'

### ************************************************************************************************************
#### if user get error object locked - can fix it in smartconsole -> manage & settings -> Sessions -> View sessions -> publish locked session
