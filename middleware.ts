import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import aj, { detectBot, shield } from "./lib/arcjet";

const validate = aj
  .withRule(
    shield({
      mode: "LIVE",
    })
  )
  .withRule(
    detectBot({
      mode: "LIVE",
      allow: ["CATEGORY:SEARCH_ENGINE", "G00G1E_CRAWLER"],
    })
  );

export async function middleware(request: NextRequest) {
  // 1. Check auth first (lightweight)
  const session = await auth.api.getSession({
    headers: request.headers,
  });

  if (!session) {
    return NextResponse.redirect(new URL("/sign-in", request.url));
  }

  // 2. Then run Arcjet validation
  const decision = await validate.protect(request);

  if (decision.isDenied()) {
    return NextResponse.json(
      { error: "Forbidden", reason: decision.reason },
      { status: 403 }
    );
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|sign-in|assets).*)"],
};