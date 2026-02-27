export const sessionOptions = {
  password: process.env.SESSION_SECRET as string,
  cookieName: "hkv_session",
  cookieOptions: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "strict" as const,
    maxAge: 60 * 15,
  },
};