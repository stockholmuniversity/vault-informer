# TODO

* Use `pyinotify` to "tail" the audit log
* Only "act" on log entries ([these docs](https://support.hashicorp.com/hc/en-us/articles/360000995548-Audit-and-Operational-Log-Details) might be useful)
    * with the `"type": "response"` since a request might fail/get denied (see [these docs](https://developer.hashicorp.com/vault/tutorials/monitoring/monitor-telemetry-audit-splunk#vault-audit-device-entries))
    * where `"request": { "operation": "..." }` is:
        * `create`
        * `update`
        * `delete`
* Send the `request` object in the message
    * Filter out sensitive data (i.e. all `hmac-` values)
        * When an object only has a string `hmac` value don't send that key-value pair e.g. `client_token`
        * When an object has a object with `hmac` values only send the keys e.g. `data` object
* Use [entrypoints to use a plugin](https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins/) based system for where to write the events

# Test cases
Use data in `tests/*.json`
## Logrotate
`logrotate -s $PWD/meow logrotatevault.conf` worked IIRC?
### logrotate copy
### logrotate move
## Vault HUP (file close and open?)




# References
https://docs.pytest.org/en/stable/how-to/tmp_path.html

