import authApiRquest from "@/apiRequest/auth";
import { LoginBodyType } from "@/schemaValidations/auth.schema";
import { cookies } from "next/headers";
import jwt from "jsonwebtoken";

export async function POST(request: Request) {
    const body = await request.json() as LoginBodyType;
    const cookieStorage = await cookies();

    try {
        const {payload} = await authApiRquest.sLogin(body)
        const { accessToken, refreshToken } = payload.data;
        const decodedAccessToken = jwt.decode(accessToken) as {exp: number} | null;
        const decodedRefreshToken = jwt.decode(refreshToken) as {exp: number} | null;

        cookieStorage.set("accessToken", accessToken, {
            path: "/",
            httpOnly: true,
            sameSite: "lax",
            expires: (decodedAccessToken?.exp ?? 0) * 1000
        });

        cookieStorage.set("refreshToken", refreshToken, {
            path: "/",
            httpOnly: true,
            sameSite: "lax",
            expires: (decodedRefreshToken?.exp ?? 0) * 1000
        })

        return Response.json(payload)
    } catch (error) {
        if (error instanceof Error) {
            return Response.json({ message: error.message }, { status: 400 });
        }else{
            return Response.json({ message: "An unexpected error occurred." }, { status: 500 });
        }
    }
}