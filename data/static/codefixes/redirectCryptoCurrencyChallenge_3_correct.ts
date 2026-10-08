export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  if (typeof url !== 'string') return false
  try {
    const target = new URL(url)
    if (target.username !== '' || target.password !== '') return false
    return [...redirectAllowlist].some(allowedUrl => target.href === new URL(allowedUrl).href)
  } catch {
    return false
  }
}