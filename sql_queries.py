NOT_NULL_CVE_QUERY = """
select
	id,
	'group_' || DENSE_RANK() OVER (ORDER BY cve, endpoint) AS tag
from vuln
where cve!='null'
"""

NULL_CVE_QUERY = """
select id
from vuln
where cve='null'
"""

SELECT_QUERY = """
select {columns}
from vuln
"""
