export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (user?.data?.email === undefined) {
      res.status(401).json({ error: 'Authentication required' })
      return
    }
    if (typeof req.body.message !== 'string') {
      res.status(400).json({ error: 'Invalid review' })
      return
    }
    db.reviewsCollection.update(
      { _id: req.body.id },
      { $set: { message: security.sanitizeHtml(req.body.message), author: user.data.email } },
      { multi: true }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}