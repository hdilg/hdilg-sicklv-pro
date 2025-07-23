export default async (request, context) => {
  const country = context.geo?.country?.code;

  if (country === "SA") {
    return Response.redirect("https://sicklv.shop/sa-access", 302);
  }

  return context.next();
};