"""Centralized local explanation & translation service (English, Hindi, Hinglish).

Design rules:
- Completely separate from detection and risk-scoring logic.
- Uses predefined local translations with safe fallback to English.
- Never sends user URLs or messages to external translation services.
- Preserves Unicode/Hindi text cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.indicators import RuleFinding

SUPPORTED_LANGUAGES: tuple[str, ...] = ("en", "hi", "hinglish")

# Predefined translations per rule_id -> lang -> (explanation, recommendation)
RULE_TRANSLATIONS: dict[str, dict[str, tuple[str, str]]] = {
    "url_shortener": {
        "en": (
            "This URL uses a shortened link, which hides the final destination.",
            "Verify shortened links with the sender before clicking.",
        ),
        "hi": (
            "यह URL shortened link का उपयोग करता है, जिससे असली destination छिप सकता है।",
            "क्लिक करने से पहले भेजने वाले से असली लिंक की पुष्टि करें।",
        ),
        "hinglish": (
            "Ye URL shortened link use karta hai, jiski wajah se asli destination hide ho sakta hai.",
            "Click karne se pehle sender se asli link verify karein.",
        ),
    },
    "suspicious_domain_structure": {
        "en": (
            "The URL has an unusual domain or structural pattern (such as an IP address, excessive subdomains, or obfuscation).",
            "Inspect the main domain name carefully before trusting this link.",
        ),
        "hi": (
            "इस URL का डोमेन या संरचना असामान्य है (जैसे IP पता, बहुत अधिक सबडोमेन, या अस्पष्ट अक्षर)।",
            "इस लिंक पर भरोसा करने से पहले मुख्य डोमेन नाम को ध्यान से जांचें।",
        ),
        "hinglish": (
            "Is URL ka domain ya structure unusual hai (jaise IP address, zyada subdomains, ya obfuscation).",
            "Is link par bharosa karne se pehle main domain dhyan se check karein.",
        ),
    },
    "missing_https": {
        "en": (
            "This URL uses unencrypted HTTP instead of HTTPS. Missing HTTPS alone does not mean a site is malicious, but sensitive data should not be entered.",
            "Never enter passwords, OTPs, or payment details on non-HTTPS pages.",
        ),
        "hi": (
            "यह URL सुरक्षित HTTPS के बजाय बिना एन्क्रिप्शन वाले HTTP का उपयोग करता है। केवल HTTP होना खतरे का पक्का सबूत नहीं है, लेकिन संवेदनशील जानकारी न भरें।",
            "HTTP पेज पर कभी भी पासवर्ड, OTP या बैंक जानकारी न डालें।",
        ),
        "hinglish": (
            "Ye URL HTTPS ki jagah bina encryption wale HTTP ka use karta hai. Sirf HTTP hona khatre ka proof nahi hai, par sensitive data na daalein.",
            "Non-HTTPS page par kabhi bhi password, OTP, ya payment details enter na karein.",
        ),
    },
    "lookalike_domain": {
        "en": (
            "The domain resembles or impersonates a well-known brand using look-alike spelling or characters.",
            "Do not log in through this link; open the official website directly.",
        ),
        "hi": (
            "यह डोमेन मिलते-जुलते अक्षरों या स्पेलिंग का उपयोग करके किसी प्रसिद्ध ब्रांड की नकल करने जैसा दिखता है।",
            "इस लिंक से लॉग इन न करें; सीधे आधिकारिक वेबसाइट खोलें।",
        ),
        "hinglish": (
            "Ye domain look-alike spelling ya characters use karke kisi known brand ki nakal jaisa lagta hai.",
            "Is link se login na karein; seedha official website kholein.",
        ),
    },
    "credential_url_pattern": {
        "en": (
            "The URL contains login, password, KYC, or verification keywords. Combined with other signals, this may indicate credential harvesting.",
            "Verify the exact domain name before entering any password, OTP, or KYC details.",
        ),
        "hi": (
            "इस URL में login, password, KYC या verification जैसे शब्द हैं। अन्य संकेतों के साथ यह जानकारी चुराने का प्रयास हो सकता है।",
            "कोई भी पासवर्ड, OTP या KYC जानकारी डालने से पहले सही डोमेन की जांच करें।",
        ),
        "hinglish": (
            "Is URL mein login, password, KYC, ya verification jaise words hain. Dusre signals ke saath ye credential harvesting ho sakta hai.",
            "Password, OTP, ya KYC details dalne se pehle exact domain verify karein.",
        ),
    },
    "suspicious_redirect": {
        "en": (
            "The URL includes a redirect query parameter that may forward you to another destination.",
            "Confirm you trust both the host website and the redirect target.",
        ),
        "hi": (
            "इस URL में एक redirect पैरामीटर है जो आपको किसी दूसरी वेबसाइट पर भेज सकता है।",
            "सुनिश्चित करें कि आप मुख्य वेबसाइट और अगले गंतव्य दोनों पर भरोसा करते हैं।",
        ),
        "hinglish": (
            "Is URL mein redirect query parameter hai jo aapko kisi aur destination par bhej sakta hai.",
            "Confirm karein ki aap host site aur redirect target dono par bharosa karte hain.",
        ),
    },
    "nested_redirect": {
        "en": (
            "A query parameter embeds another external or encoded URL, which can disguise where the link ultimately leads.",
            "Inspect the embedded destination domain carefully before clicking.",
        ),
        "hi": (
            "URL के अंदर एक और बाहरी या एन्कोडेड लिंक छिपा है, जिससे असली वेबसाइट की पहचान छिप सकती है।",
            "क्लिक करने से पहले अंदर छिपे लिंक के डोमेन की ध्यान से जांच करें।",
        ),
        "hinglish": (
            "URL ke query parameter mein ek aur external ya encoded link chhupa hai, jo asli destination hide kar sakta hai.",
            "Click karne se pehle embedded destination domain dhyan se check karein.",
        ),
    },
    "deceptive_redirect_chain": {
        "en": (
            "During read-only inspection, the link redirected to a different domain than the original URL.",
            "Verify that you intended to visit the final destination domain.",
        ),
        "hi": (
            "सुरक्षित जांच के दौरान यह लिंक शुरुआती पते से अलग किसी दूसरे डोमेन पर रीडायरेक्ट हुआ।",
            "पुष्टि करें कि आप वास्तव में अंतिम वेबसाइट पर ही जाना चाहते थे।",
        ),
        "hinglish": (
            "Read-only inspection ke dauran ye link original URL se alag domain par redirect hua.",
            "Verify karein ki aap final destination domain par hi jaana chahte the.",
        ),
    },
    "suspicious_file_download": {
        "en": (
            "The URL points to an executable or script file extension. This is a risk signal only, not confirmation of malware.",
            "Do not download or run executable files from unsolicited links.",
        ),
        "hi": (
            "यह URL एक executable या script फ़ाइल की ओर इशारा करता है। यह केवल एक जोखिम संकेत है, मैलवेयर की पुष्टि नहीं।",
            "अनजान या संदिग्ध लिंक से कभी भी executable फ़ाइल डाउनलोड या इंस्टॉल न करें।",
        ),
        "hinglish": (
            "Ye URL executable ya script file extension reference karta hai. Ye sirf ek risk signal hai, malware confirmation nahi.",
            "Anjaan links se executable files download ya run na karein.",
        ),
    },
    "page_brand_impersonation": {
        "en": (
            "The inspected page content references a major brand while hosted on an unrelated domain.",
            "Do not enter credentials; navigate directly to the brand's official website.",
        ),
        "hi": (
            "जांचे गए पेज की सामग्री एक बड़े ब्रांड का नाम दिखाती है, जबकि यह किसी अलग डोमेन पर होस्ट है।",
            "लॉग इन जानकारी न डालें; सीधे ब्रांड की आधिकारिक वेबसाइट पर जाएं।",
        ),
        "hinglish": (
            "Inspected page content ek known brand ka naam dikhata hai jabki domain alag hai.",
            "Credentials enter na karein; seedha brand ki official website par jayein.",
        ),
    },
    "suspicious_form_destination": {
        "en": (
            "An HTML form on the inspected page submits data to an unrelated external domain.",
            "Never submit passwords or personal details to forms pointing to external domains.",
        ),
        "hi": (
            "इस पेज का एक फ़ॉर्म डेटा को किसी दूसरे बाहरी डोमेन पर भेजता है, जो फिशिंग का मजबूत संकेत है।",
            "बाहरी डोमेन पर डेटा भेजने वाले फ़ॉर्म में कभी भी पासवर्ड या निजी जानकारी न भरें।",
        ),
        "hinglish": (
            "Is page ka HTML form data ko kisi unrelated external domain par submit karta hai.",
            "External domain par submit karne wale forms mein kabhi password ya personal details na bharein.",
        ),
    },
    "strong_credential_harvesting": {
        "en": (
            "The page collects password or OTP inputs alongside mismatched brand identity or suspicious form routing.",
            "Close this page immediately and do not enter any password, OTP, or banking details.",
        ),
        "hi": (
            "यह पेज गलत ब्रांड पहचान या संदिग्ध फ़ॉर्म के साथ पासवर्ड या OTP मांग रहा है, जो क्रेडेंशियल चोरी का मजबूत संकेत है।",
            "इस पेज को तुरंत बंद करें और कोई भी पासवर्ड, OTP या बैंक विवरण साझा न करें।",
        ),
        "hinglish": (
            "Ye page mismatched brand identity ya suspicious form ke saath password/OTP maang raha hai.",
            "Is page ko turant band karein aur koi bhi password, OTP, ya bank detail share na karein.",
        ),
    },
    "suspicious_third_party_script": {
        "en": (
            "The page loads JavaScript from an IP address or unusual top-level domain.",
            "Avoid interacting with pages that load scripts from untrusted hosts.",
        ),
        "hi": (
            "यह पेज किसी IP पते या असामान्य डोमेन से JavaScript लोड करता है।",
            "अविश्वसनीय स्रोतों से स्क्रिप्ट लोड करने वाले पेज से सावधान रहें।",
        ),
        "hinglish": (
            "Ye page kisi IP address ya unusual domain se JavaScript load karta hai.",
            "Untrusted hosts se script load karne wale pages se interact karne se bachein.",
        ),
    },
    "phishing_reputation_match": {
        "en": (
            "An external threat-intelligence provider flagged this URL as phishing.",
            "Do not open this link or enter any credentials.",
        ),
        "hi": (
            "एक बाहरी सुरक्षा प्रदाता (threat-intelligence) ने इस URL को फिशिंग के रूप में चिह्नित किया है।",
            "इस लिंक को न खोलें और कोई भी लॉग इन जानकारी न डालें।",
        ),
        "hinglish": (
            "Ek external threat-intelligence provider ne is URL ko phishing flag kiya hai.",
            "Is link ko open na karein aur koi bhi credentials enter na karein.",
        ),
    },
    "malware_reputation_match": {
        "en": (
            "An external threat-intelligence provider flagged this URL or domain for malware distribution.",
            "Do not visit this link or download any files from it.",
        ),
        "hi": (
            "एक बाहरी सुरक्षा प्रदाता ने इस URL या डोमेन को मैलवेयर फैलाने वाला बताया है।",
            "इस लिंक पर न जाएं और इससे कोई भी फ़ाइल डाउनलोड न करें।",
        ),
        "hinglish": (
            "Ek external threat-intelligence provider ne is URL/domain ko malware distribution ke liye flag kiya hai.",
            "Is link par na jayein aur koi bhi file download na karein.",
        ),
    },
}


@dataclass(frozen=True)
class LocalizedExplanationBundle:
    """Localized summary, per-rule explanations, and recommendations."""

    summary: str
    explanations: list[str]
    recommendations: list[str]


def build_risk_summary(
    *,
    risk_score: int | None,
    risk_level: str,
    detected_count: int,
    lang: str,
) -> str:
    """Generate a plain-language summary explaining why the scan received its score & level."""
    if risk_score is None or risk_level == "Unavailable":
        if lang == "hi":
            return "कोई URL नहीं मिला — URL-आधारित जोखिम मूल्यांकन उपलब्ध नहीं है।"
        if lang == "hinglish":
            return "Koi URL detect nahi hua — URL-based risk assessment unavailable hai."
        return "No URL detected — URL-based risk assessment unavailable."

    if risk_level == "Dangerous":
        if lang == "hi":
            return (
                f"जोखिम स्कोर {risk_score}/100 (Dangerous): {detected_count} गंभीर संकेत मिले हैं "
                "जो फिशिंग या संदिग्ध गतिविधि की ओर इशारा करते हैं। इस लिंक से दूर रहें।"
            )
        if lang == "hinglish":
            return (
                f"Risk score {risk_score}/100 (Dangerous): {detected_count} strong indicators mile hain "
                "jo phishing ya suspicious activity dikhate hain. Is link se door rahein."
            )
        return (
            f"Risk score {risk_score}/100 (Dangerous): {detected_count} strong indicator(s) "
            "detected. Avoid interacting with this link."
        )

    if risk_level == "Suspicious":
        if lang == "hi":
            return (
                f"जोखिम स्कोर {risk_score}/100 (Suspicious): {detected_count} संदिग्ध संकेत मिले हैं। "
                "आगे बढ़ने से पहले आधिकारिक वेबसाइट या ऐप से जांच करें।"
            )
        if lang == "hinglish":
            return (
                f"Risk score {risk_score}/100 (Suspicious): {detected_count} suspicious indicators mile hain. "
                "Aage badhne se pehle official website ya app se verify karein."
            )
        return (
            f"Risk score {risk_score}/100 (Suspicious): {detected_count} suspicious indicator(s) "
            "detected. Verify independently via official channels before proceeding."
        )

    if risk_level == "No strong indicators detected":
        if lang == "hi":
            return (
                f"जोखिम स्कोर {risk_score}/100 (No strong indicators detected): उपलब्ध जांच में कोई बड़ा खतरा नहीं मिला, "
                "लेकिन यह 100% सुरक्षा की गारंटी नहीं है।"
            )
        if lang == "hinglish":
            return (
                f"Risk score {risk_score}/100 (No strong indicators detected): Available checks mein koi bada threat nahi mila, "
                "lekin ye 100% safety ki guarantee nahi hai."
            )
        return (
            f"Risk score {risk_score}/100 (No strong indicators detected): Available checks found "
            "no strong evidence, though safety is never guaranteed."
        )

    # Inspection unavailable (URL-only or blocked/failed)
    if lang == "hi":
        return (
            f"जोखिम स्कोर {risk_score}/100 (Inspection unavailable): केवल URL टेक्स्ट की जांच हुई है; "
            "वेबसाइट की सामग्री नहीं जांची गई, इसलिए पूर्ण सुरक्षा की पुष्टि नहीं हो सकती।"
        )
    if lang == "hinglish":
        return (
            f"Risk score {risk_score}/100 (Inspection unavailable): Sirf URL text check hua hai; "
            "website content inspect nahi hua, isliye safety verified nahi hai."
        )
    return (
        f"Risk score {risk_score}/100 (Inspection unavailable): URL-only analysis was performed; "
        "website content was not inspected."
    )


def generate_multilingual_explanations(
    *,
    risk_score: int | None,
    risk_level: str,
    detected_rules: list[RuleFinding],
    fallback_recommendations: list[str],
) -> dict[str, LocalizedExplanationBundle]:
    """Build localized explanations for English ('en'), Hindi ('hi'), and Hinglish ('hinglish')."""
    bundles: dict[str, LocalizedExplanationBundle] = {}

    for lang in SUPPORTED_LANGUAGES:
        summary = build_risk_summary(
            risk_score=risk_score,
            risk_level=risk_level,
            detected_count=len(detected_rules),
            lang=lang,
        )

        explanations: list[str] = []
        recommendations: list[str] = []
        seen_recs: set[str] = set()

        for rule in detected_rules:
            rule_entry = RULE_TRANSLATIONS.get(rule.rule_id)
            if rule_entry and lang in rule_entry:
                exp_text, rec_text = rule_entry[lang]
            else:
                # Safe fallback to English when a specific rule translation is unavailable
                exp_text = rule.explanation
                rec_text = rule.recommendation

            explanations.append(exp_text)
            if rec_text and rec_text not in seen_recs:
                seen_recs.add(rec_text)
                recommendations.append(rec_text)

        if not recommendations:
            if lang == "hi":
                recommendations = [
                    "किसी भी अनजान लिंक पर क्लिक करने से पहले भेजने वाले और डोमेन की आधिकारिक वेबसाइट से पुष्टि करें।"
                ]
            elif lang == "hinglish":
                recommendations = [
                    "Kisi bhi unknown link par click karne se pehle sender aur domain ko official website se verify karein."
                ]
            else:
                recommendations = list(fallback_recommendations)

        bundles[lang] = LocalizedExplanationBundle(
            summary=summary,
            explanations=explanations,
            recommendations=recommendations,
        )

    return bundles
