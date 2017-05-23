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

## String operations

### RSPLIT(string, n [, char])

Splits a string on character `char` (default `.`) and selects the N'th split
from the right, i.e: `RSPLIT("192.168.0.1",2)` returns 168.

### NAME(table, num)

Translate numbers into names table can be `rcode` or `qtype`, i.e:
`name("rcode",rcode)` returns `NXDomain`.

### TRIM(string, trim)

Trims of any occurrences of the string `trim` from both end of the string,
i.e: `trim("se.domains.se", "se")` returns `.domains.`.

### LOWER(string)

Turns `string` into lowercase.
