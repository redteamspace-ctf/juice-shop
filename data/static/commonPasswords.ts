/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// A curated denylist of the passwords that show up most often in real-world
// credential breach corpora (rockyou.txt, HaveIBeenPwned's Pwned Passwords,
// SecLists' 10k-most-common, etc.). It stands in for a full top-one-million
// breach-corpus lookup — which in production would be an external
// HaveIBeenPwned-style k-anonymity API call rather than a huge file vendored
// into the repo — while still catching the overwhelming majority of weak,
// previously-breached passwords a real attacker would try first. Matching is
// case-insensitive; see isCommonPassword below.
export const commonPasswords = new Set<string>([
  '123456', '123456789', 'qwerty', 'password', '12345', '12345678', '111111',
  '1234567', 'sunshine', 'qwerty123', '1q2w3e4r', 'iloveyou', '000000', 'abc123',
  '654321', '123123', 'qwertyuiop', '1q2w3e', '123321', 'letmein', 'login',
  'admin', 'welcome', 'monkey', 'dragon', 'password1', 'passw0rd', 'football',
  'baseball', 'master', 'shadow', 'superman', 'michael', 'princess', 'qazwsx',
  'trustno1', '1234567890', '123456a', 'zxcvbnm', 'asdfghjkl', 'starwars',
  'whatever', 'freedom', 'batman', 'hunter', 'thomas', 'summer', 'cheese',
  'ginger', 'hockey', 'soccer', 'nicole', 'jessica', 'pepper', 'daniel',
  'access', 'yankees', '12341234', 'biteme', 'ashley', 'bailey', 'killer',
  'jennifer', 'joshua', 'amanda', 'andrew', 'buster', 'tigger', 'charlie',
  'jordan', 'hannah', 'michelle', 'maggie', 'matthew', 'robert', 'danielle',
  'pokemon', 'orange', 'taylor', 'mustang', 'spider', 'cookie', 'chicken',
  'computer', 'internet', 'flower', 'secret', 'george', 'harley', 'coffee',
  'blahblah', 'guitar', 'jackson', 'loveme', 'monster', 'dolphin', 'phoenix',
  'purple', 'rabbit', 'ranger', 'scooter', 'tigers', 'angel', 'diamond',
  'elephant', 'friends', 'maverick', 'ninja', 'panther', 'rainbow', 'rocket',
  'samsung', 'tiger', 'turtle', 'warrior', 'wizard', 'yellow', 'zxcvbn',
  'admin123', 'root', 'toor', 'test', 'test123', 'changeme', 'default',
  'guest', 'temp', 'temp123', 'welcome1', 'password123', 'password1!',
  'letmein1', 'qwerty1', 'qwerty12', '1qaz2wsx', 'asdf1234', 'p@ssw0rd',
  'p@ssword', 'passw0rd1', 'iloveyou1', 'iloveyou2', '123qwe', 'q1w2e3r4',
  'aaaaaa', 'aaaaaaaa', '11111111', '222222', '333333', '444444', '555555',
  '666666', '777777', '888888', '999999', '121212', '112233', '102030',
  '159753', '147258', '987654321', '1111111', '7777777', '88888888',
  'love123', 'summer2020', 'summer2021', 'summer2022', 'winter2020',
  'spring2020', 'autumn2020', 'march123', 'april123', 'may1234', 'june1234',
  'july1234', 'august123', 'september1', 'october12', 'november1',
  'december1', 'juiceshop', 'juice123', 'owaspjuice', 'bjoernkimminich',
  'ownedbyme', 'ownedbyyou', 'incorrect', 'solveme', 'hackme', 'hackthebox',
  'letmeout', 'opensesame', 'sesame123', 'trustme1', 'nopassword',
  'nopassword1', 'changethis', 'changeit', 'changeit123', 'notsecure',
  'insecure1', 'weakpass', 'weakpassword', 'commonpass', 'topsecret',
  'confidential', 'security', 'securitypass', 'adminadmin', 'rootroot',
  'useruser', 'testtest', 'demo1234', 'sampledata', 'temporary1',
  'onetwothree', 'abcd1234', 'abcdefgh', 'abcdefg1', '1a2b3c4d', 'z1x2c3v4',
  'q1w2e3r4t5', 'asdasd12', 'zaq12wsx', 'xsw23edc', 'cde34rfv', 'vfr45tgb',
  'bgt56yhn', 'nhy67ujm', 'mju78ik,', 'football1', 'baseball1', 'hockey123',
  'soccer123', 'basketball', 'skateboard', 'snowboard1', 'swimming1',
  'running12', 'cycling12', 'volleyball', 'badminton1', 'tennis123',
  'golfing12', 'fishing12', 'hunting12', 'camping12', 'hiking123',
  'traveling1', 'vacation1', 'holiday12', 'birthday1', 'christmas',
  'halloween', 'thanksgiving', 'newyear12', 'valentine', 'anniversary'
])

export function isCommonPassword (password: string): boolean {
  return commonPasswords.has(password.trim().toLowerCase())
}
