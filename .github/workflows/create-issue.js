
module.exports = async ({github, context, image, json_file}) => {
           const fs = require('fs');
           console.log(json_file)
            let data = fs.readFileSync(json_file, 'utf8');
            console.log(data)
            data = JSON.parse(data)
            data = data.matches;
            console.log("data")

            const { owner, repo } = context.repo;
            const regex = /^(?:.*\/)?([^/]+)$/;
            const labels = ['security', 'docker scan failed', `${image.match(regex)?.[1]}`];

            const vulnerabilities = data.map(item => item.vulnerability);

            // Extracting severities
            const severities = vulnerabilities.map(item => item.severity);

            // Counting the occurrences of each severity level
            const countBySeverity = severities.reduce((acc, severity) => {
              acc[severity] = (acc[severity] || 0) + 1;
              return acc;
            }, {});

            console.log("Count by Severity:", countBySeverity);

            let markdown = "| Image | Low | High | Medium | Critical | Scan Location |\n";
            markdown += "| --- | --- | --- | --- | --- | --- |\n";
            markdown += `| ${ image } |`;
            for (const severity of ["Low", "High", "Medium", "Critical"]) {
              markdown += ` ${countBySeverity[severity] || 0} |`;
            }
            markdown += ` [${ github.run_id }](https://github.com/${owner}/${repo}/actions/runs/${ github.run_id }) |\n`;

            console.log(markdown);

            let commentMarkdown = "";

            // Table headers
            commentMarkdown += "| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n";
            commentMarkdown += "| --- | --- | --- | --- | --- | --- | --- | --- |\n";
            let highVulnerabilityMarkdown = ""
            let criticalVulnerabilityMarkdown = ""
            let vulnerabilityMarkdown = ""
            data.forEach((match) => {
              if(match.vulnerability.severity == "High" ) {
                vulnerabilityMarkdown = `| ${match.vulnerability.severity} | ${match.artifact.name} | ${match.artifact.version} | ${match.vulnerability.fix.versions || ""} | ${match.artifact.type} | ${match.artifact.locations[0].path} | ${match.vulnerability.namespace} | [${match.vulnerability.id}](${match.vulnerability.dataSource}) |\n`;
                if (highVulnerabilityMarkdown.length + vulnerabilityMarkdown.length <= 65400) 
                    highVulnerabilityMarkdown += vulnerabilityMarkdown;
                }
              
                if(match.vulnerability.severity == "Critical") {
                    vulnerabilityMarkdown = `| ${match.vulnerability.severity} | ${match.artifact.name} | ${match.artifact.version} | ${match.vulnerability.fix.versions || ""} | ${match.artifact.type} | ${match.artifact.locations[0].path} | ${match.vulnerability.namespace} | [${match.vulnerability.id}](${match.vulnerability.dataSource}) |\n`;
                    if (criticalVulnerabilityMarkdown.length + vulnerabilityMarkdown.length <= 65400) 
                    criticalVulnerabilityMarkdown += vulnerabilityMarkdown;
                }
            });

            criticalVulnerabilityMarkdown = commentMarkdown + criticalVulnerabilityMarkdown

            console.log("High Vul\n", commentMarkdown + highVulnerabilityMarkdown)
            console.log("Critical Vul\n", criticalVulnerabilityMarkdown)
            
            const existingIssue = (await github.paginate(github.rest.issues.listForRepo.endpoint.merge({
              owner, repo, state: 'open',labels
            }))).filter(i => i.title.indexOf('Docker image security scan') !== -1)[0];
            
            const body = `Workflow failed for commit ${github.sha}.
            Detected vulnerabilities in \`${image}\` docker image.
            ${markdown}
                `;
        
            if (existingIssue) {
              github.rest.issues.update({ owner, repo, issue_number: existingIssue.number, body });
            } else {
              const response = await github.rest.issues.create({
                owner, repo,
                title : '🛡️ Docker image security scan failed 🛡️',
                body,
                labels
            });

            const commentBody = `Workflow failed for commit ${ github.sha }.

            Following Critical vulnerabilities have been detected:
                  ${criticalVulnerabilityMarkdown}
                `;
                github.rest.issues.createComment({
                  issue_number: response.data.number,
                  owner, repo,
                  body: commentBody
                });       
            }   

    }