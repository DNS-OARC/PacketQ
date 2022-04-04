# PacketQ SQL functions

## Grouping functions

Grouping function either groups the whole result or the result specified
by `group by`.

### COUNT(wildcard)

Counts occurrences within a group.

### AVG(num)

Calculates the average of all `num` within a group.

### SUM(num)

Calculates the sum of all `num` within a group.

### MIN(num)

Calculates the minimum of all `num` within a group.

### MAX(num)

Calculates the maximum of all `num` within a group.

### STDEV(num)

Calculates the standard deviation of all `num` within a group.

## Integer functions

### TRUNCATE(num)

Converts double precision number to integer.

## Logical functions

### IF(condition, true_op, false_op)

Evaluates `condition` and executes `false_op` if the result is 0 (false)
otherwise `true_op` is executed.

### NETMASK(address [, v4_mask_length [, v6_mask_length]])

Masks the specified address using the v4 and v6 mask lengths specified
in number of bits.

Defaults to 24 for IPv4 and 48 for IPv6 (/24 and /48 respectively)

### CC(address)

Returns the 2-letter ISO country code associated with the address from
a MaxMind database (see MaxMind Database below on selecting database).

Returns an empty string on lookup failures or if this feature was not
built in.

### ASN(address)

Returns the autonomous system number associated with the address from
a MaxMind database (see MaxMind Database below on selecting database).

Returns -1 on lookup failures or if this feature was not built in.

## String operations

### RSPLIT(string, n [, char])

Splits a string on character `char` (default `.`) and selects the N'th split
from the right, i.e: `RSPLIT('192.168.0.1',2)` returns 168.

### NAME(table, num)

Translate numbers into names table can be `rcode` or `qtype`, i.e:
`name('rcode',rcode)` returns `NXDomain`.

### TRIM(string, trim)

Trims of any occurrences of the string `trim` from both end of the string,
i.e: `trim('se.domains.se', 'se')` returns `.domains.`.

### LOWER(string)

Turns `string` into lowercase.

# MaxMind Database

PacketQ will try to open MaxMind databases that resides in common path on
major distributions, but you can also specify paths and database files
using environment variables.

`PACKETQ_MAXMIND_PATH` sets the path to look for the databases in addition
to the common paths, it will try `GeoLite2-Country.mmdb` for `CC()` and
`GeoLite2-ASN.mmdb` for `ASN()`.

You can also specify the full path to the database file you wish to use
for each function with `PACKETQ_MAXMIND_CC_DB` and `PACKETQ_MAXMIND_ASN_DB`,
these settings will override path settings.
