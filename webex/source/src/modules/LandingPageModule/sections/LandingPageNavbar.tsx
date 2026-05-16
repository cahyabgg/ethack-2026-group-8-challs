import Navbar from "@/components/commons/Navbar";
import { useShop } from "@/context/ShopProvider";
import { Star } from "lucide-react";
import Link from "next/link";


export default function LandingPageNavbar() {
    const {isAuthenticated } = useShop();

    if (isAuthenticated) {
        return <Navbar/>
    }
    return (
        <nav className="flex items-center justify-between px-8 py-4">
            <Link href="/">
            <div className="flex items-center gap-2 text-2xl font-extrabold">
                <Star className="h-6 w-6 text-blue-600" />
                Stride
            </div>
            </Link>
            
        </nav>
    );
}