# GreenNetSec

My goal for this project was to create an imaginary use case where we are using Cisco Catalyst Center as a network management tool and we want to determine how energy efficient out device configurations are, and what our security posture looks like from a configuration perspective. Although a tool like Catalyst Center does a great job of getting you all the data you need to make these determinations it could be a daunting task trying to analyze the data of thousands of devices in a manual way. This is where AI can be a great helper by performing the data analysis for us. With this project I wanted to demonstrate the "art of possible" when it comes to consuming AI in a programmatic manner to understand the overall "green" and security posture of our network devices.  This code is for educational purposes only and must NOT be used in a production environment.

You can fully test this app by using the Cisco Catalyst Center Sandbox and your own OpenAi api key. The app will connect to a Cisco Catalyst Center, get device inventory, fetch various "show" commands from all devices, and finally send this data to be processed by openai by using the gpt-3.5-turbo-0125 model. The prompt that we have provided for any given request is:

"Analyze the following Cisco network device configuration for energy-saving opportunities and potential security vulnerabilities. Provide actionable recommendations as bullet points and estimate potential energy savings as a percentage")

The results of an analysis are stored in the current running directory of the app and are named "ai_analysis_report.xlsx"


## Usage/Examples

```
- Set your openai key as an environment variable named 'OPEN_API_KEY'.
- Optionally set your Cisco Console API Key and Secret to get CVE info on devices. The variables should be named 'PSIRT_API_KEY' and 'PSIRT_API_SECRET.

- Prior to running the program install requirements.txt
- To run program "python3 greennetsec.py" and follow prompts.
- The program will take a while to run depending on the number of devices in inventory.
  A progress bar indicates that the analysis is still underway.

Sandbox Credentials
url: sandboxdnac.cisco.com
username: devnetuser
password: Cisco123!
```

