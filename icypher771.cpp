#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

using namespace std;

void showBanner() {
    cout << "\033[1;36m";
    cout << " ██╗ ██████╗██╗   ██╗██████0╗██╗  ██╗███████╗██████╗ ██████╗ ██████╗ \n";
    cout << " ██║██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗╚════██╗╚════██╗\n";
    cout << " ██║██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝ █████╔╝ █████╔╝ \n";
    cout << " ██║██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗ ╚═══██╗ ╚═══██╗ \n";
    cout << " ██║╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║██████╔╝██████╔╝ \n";
    cout << " ╚═╝ ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝╚═╝  ╚═╝  \n";
    cout << "                 // C++ ADVANCED URL THREAT AUDITOR v1.0 //\n";
    cout << "\033[0m" << endl;
}

int main(int argc, char* argv[]) {
    showBanner();
    
    if (argc < 2) {
        cout << "\033[1;33mUsage: ./icypher771 <URL>\033[0m" << endl;
        cout << "Example: ./icypher771 https://example.com/login" << endl;
        return 1;
    }

    string url = argv[1];
    cout << "\033[1;33m[*] Analyzing target URL: " << url << "\033[0m\n\n";

    int risk_score = 0;
    vector<string> threats;

    // 1. Protocol check
    if (url.rfind("http://", 0) == 0) {
        risk_score += 20;
        threats.push_back("Insecure Protocol (HTTP used instead of HTTPS)");
    } else {
        cout << "    \033[1;32m[✓] Secure HTTPS protocol detected.\033[0m\n";
    }

    // 2. Suspicious TLDs
    vector<string> bad_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"};
    for (const auto& tld : bad_tlds) {
        if (url.find(tld) != string::npos) {
            risk_score += 35;
            threats.push_back("Suspicious Top-Level Domain (TLD) detected.");
            break;
        }
    }

    // 3. Phishing Keywords
    vector<string> keywords = {"login", "verify", "update", "secure", "account", "banking", "signin"};
    string lower_url = url;
    transform(lower_url.begin(), lower_url.end(), lower_url.begin(), ::tolower);
    
    for (const auto& kw : keywords) {
        if (lower_url.find(kw) != string::npos) {
            risk_score += 40;
            threats.push_back("Contains sensitive/phishing keyword: " + kw);
            break;
        }
    }

    // 4. Length and Obfuscation
    if (url.length() > 75) {
        risk_score += 15;
        threats.push_back("URL length is unusually long.");
    }

    if (url.find('@') != string::npos) {
        risk_score += 50;
        threats.push_back("Critical: '@' symbol found (Redirection risk).");
    }

    // Report
    cout << "\n\033[1;36m----------------- AUDIT REPORT -----------------\033[0m\n";
    cout << "    - Risk Score: " << risk_score << "/100\n";
    
    if (risk_score == 0) {
        cout << "    - Status: \033[1;32mLOW RISK / CLEAN\033[0m\n";
    } else if (risk_score < 50) {
        cout << "    - Status: \033[1;33mMODERATE RISK - Proceed with caution\033[0m\n";
    } else {
        cout << "    - Status: \033[1;31mHIGH RISK / POTENTIAL MALICIOUS URL!\033[0m\n";
    }

    if (!threats.empty()) {
        cout << "\n    \033[1;31mDetected Threat Indicators:\033[0m\n";
        for (const auto& t : threats) {
            cout << "      [!] " << t << "\n";
        }
    } else {
        cout << "\n    \033[1;32m[✔] No major threat indicators flagged.\033[0m\n";
    }
    cout << "\033[1;36m------------------------------------------------\033[0m\n";

    return 0;
}
