'use client';
import { useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";

export default function OauthCallback() {
    const router = useRouter();
    const params = useSearchParams();

    const checkUser = async () => {
        try {
            const res = await fetch("http://localhost:8000/check-user", {
                method: "GET",
                credentials: "include",
            });
            
            if (res.status === 403) {
                await fetch('/api/logout', { method: 'POST' });
                router.push("/unauthorized")
            } else if (res.status === 401) {
                router.push("/login");
            } else if (!res.ok) {
                console.error("Unexpected error:", await res.text());
            } else {
                router.push('/');
            }
        } catch (err) {
            console.error("Failed to check user:", err)
        }
    };

    useEffect(() => {
        const code = params.get('code');
        if (code) {
            fetch("http://localhost:8000/auth/callback", {
                method: "POST",
                body: JSON.stringify({ code }),
                headers: { "Content-Type": "application/json" },
                credentials: "include",
            }).then(async () => {
                await checkUser();
            });
        }
    }, [params]);

    return (
        <div className="flex items-center justify-center h-screen">
            <span className="loading loading-spinner loading-3xl" />
        </div>
    );
}