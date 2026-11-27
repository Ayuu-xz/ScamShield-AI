/**
 * Educational scam awareness content and result-based matching logic.
 * All guidance is educational and never claims that one indicator proves fraud.
 */

export const SCAM_CATEGORIES = [
  {
    id: 'kyc',
    title: 'Fake KYC Update Scams',
    iconName: 'FileWarning',
    explanation:
      'Scammers pretend to be your bank or telecom provider and claim your KYC is expired so you panic and click a fake update link.',
    warningSigns: [
      'Threats that your bank account or SIM will be blocked today',
      'Links asking you to re-enter ID numbers or card details',
    ],
    preventionTips: [
      'Check your official banking app directly instead of clicking SMS links',
      'Visit a bank branch or call the number on the back of your card',
    ],
  },
  {
    id: 'lottery',
    title: 'Lottery and Prize Scams',
    iconName: 'Gift',
    explanation:
      'Unsolicited messages claiming you won cash, a phone, or a lottery—even though you never entered a contest.',
    warningSigns: [
      'Asking for a small "processing" or "tax" fee to release winnings',
      'Rushing you to claim the prize within a few hours',
    ],
    preventionTips: [
      'Remember you cannot win a legitimate contest you never entered',
      'Never pay money to receive a prize or cash reward',
    ],
  },
  {
    id: 'job',
    title: 'Fake Job Offers',
    iconName: 'Briefcase',
    explanation:
      'Fraudulent work-from-home offers promising high daily pay for simple tasks, then demanding upfront fees.',
    warningSigns: [
      'Unrealistic daily income with no real interview process',
      'Requests for registration, training, or equipment deposits',
    ],
    preventionTips: [
      'Legitimate employers do not charge fees to hire you',
      'Verify the company on its official website before sharing documents',
    ],
  },
  {
    id: 'parcel',
    title: 'Parcel Delivery Scams',
    iconName: 'PackageX',
    explanation:
      'Fake courier texts claiming a package is stuck at customs or needs a small redelivery fee.',
    warningSigns: [
      'Unexpected delivery alerts when you did not order anything',
      'Requests for card details to pay a tiny customs or redelivery charge',
    ],
    preventionTips: [
      'Track packages only inside the shopping app or courier site you used',
      'Ignore payment links sent from unknown mobile numbers',
    ],
  },
  {
    id: 'otp',
    title: 'OTP and Banking Scams',
    iconName: 'KeyRound',
    explanation:
      'Attackers trick you into sharing a one-time passcode (OTP), PIN, or password to take over your account.',
    warningSigns: [
      'Anyone on call, chat, or a web form asking for your OTP or PIN',
      'Claims that sharing an OTP is needed to "cancel" a charge or receive money',
    ],
    preventionTips: [
      'Never share OTPs, PINs, CVVs, or passwords with anyone—even "support"',
      'You never need to enter a PIN or OTP to receive money',
    ],
  },
  {
    id: 'shortlinks',
    title: 'Suspicious Shortened Links',
    iconName: 'Link2',
    explanation:
      'Shortened or look-alike URLs hide the real website address, making it easy to disguise a phishing page.',
    warningSigns: [
      'Short links (like bit.ly or tinyurl) used for urgent bank or login alerts',
      'Misspelled brand names, extra hyphens, or raw IP addresses in the URL',
    ],
    preventionTips: [
      'Type official website addresses manually instead of tapping unexpected links',
      'Inspect the domain name carefully from right to left before logging in',
    ],
  },
]

export const SCAM_IDENTIFICATION_CHECKLIST = [
  'Unexpected requests for OTPs.',
  'Urgent threats about account blocking.',
  'Unsolicited prize or lottery messages.',
  'Requests for advance payments.',
  'Unknown or misleading links.',
  'Requests for passwords or banking details.',
]

export const BEFORE_YOU_CLICK_TIPS = [
  {
    title: 'Verify messages through official channels',
    detail: 'Open the company’s official app or website directly rather than using links in a message.',
  },
  {
    title: 'Never share OTPs or passwords',
    detail: 'Legitimate support teams never ask for your one-time passcode, PIN, or password.',
  },
  {
    title: 'Avoid unexpected payment requests',
    detail: 'Do not pay registration, customs, or processing fees for unsolicited offers or prizes.',
  },
  {
    title: 'Check domains carefully',
    detail: 'Watch for look-alike spellings, extra subdomains, and unusual endings before trusting a site.',
  },
  {
    title: 'Do not trust unexpected rewards',
    detail: 'Treat surprise lottery wins, giveaways, and instant cash claims with healthy skepticism.',
  },
  {
    title: 'Use independently verified contact details',
    detail: 'Look up customer support numbers from official statements or the back of your bank card.',
  },
]

/**
 * Match actual detected indicators from a scanResult to relevant educational
 * scam awareness cards. Returns an empty array when no indicators were found.
 *
 * @param {object | null} scanResult - Normalized scan result from api.js.
 * @returns {Array<object>} Relevant SCAM_CATEGORIES entries.
 */
export function getRelevantAwarenessCards(scanResult) {
  if (!scanResult || !Array.isArray(scanResult.detectedIndicators)) {
    return []
  }

  if (scanResult.detectedIndicators.length === 0) {
    return []
  }

  const combinedText = [
    ...scanResult.detectedIndicators,
    ...(Array.isArray(scanResult.explanations) ? scanResult.explanations : []),
  ]
    .join(' ')
    .toLowerCase()

  const matchedIds = new Set()

  if (combinedText.includes('kyc')) {
    matchedIds.add('kyc')
  }

  if (
    combinedText.includes('otp') ||
    combinedText.includes('password') ||
    combinedText.includes('sensitive info') ||
    combinedText.includes('banking')
  ) {
    matchedIds.add('otp')
  }

  if (
    combinedText.includes('reward') ||
    combinedText.includes('prize') ||
    combinedText.includes('lottery')
  ) {
    matchedIds.add('lottery')
  }

  if (
    combinedText.includes('job') ||
    combinedText.includes('registration fee') ||
    combinedText.includes('daily pay')
  ) {
    matchedIds.add('job')
  }

  if (
    combinedText.includes('parcel') ||
    combinedText.includes('delivery') ||
    combinedText.includes('customs')
  ) {
    matchedIds.add('parcel')
  }

  if (
    scanResult.scanType === 'url' ||
    combinedText.includes('shortener') ||
    combinedText.includes('suspicious link') ||
    combinedText.includes('look-alike') ||
    combinedText.includes('ip address') ||
    combinedText.includes('subdomain')
  ) {
    matchedIds.add('shortlinks')
  }

  return SCAM_CATEGORIES.filter((card) => matchedIds.has(card.id))
}
