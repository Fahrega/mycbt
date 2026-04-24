import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function Home() {
  return (
    <main className="min-h-screen flex items-center justify-center bg-background px-4">
      <div className="flex flex-col items-center gap-8 text-center max-w-sm w-full">

        {/* Logo / Brand */}
        <div className="flex flex-col gap-3">
          <h1 className="text-6xl font-bold tracking-tight text-foreground">
            MyCBT
          </h1>
          <p className="text-base text-muted-foreground">
            Platform ujian berbasis komputer yang mudah, cepat, dan terpercaya.
          </p>
        </div>

        {/* Actions */}
        <div className="flex gap-3 w-full">
          <Button asChild variant="outline" size="lg" className="flex-1">
            <Link href="/login">Login</Link>
          </Button>
          <Button asChild size="lg" className="flex-1">
            <Link href="/register">Daftar</Link>
          </Button>
        </div>

      </div>
    </main>
  );
}
