import { Star, ShoppingCart } from "lucide-react";
import { Button } from "../ui/button";
import Link from "next/link";


export default function Navbar() {
    return (
        <nav className="flex items-center justify-between px-8 py-4">
            <Link href="/">
                <div className="flex items-center gap-2 text-2xl font-extrabold">
                    <Star className="h-6 w-6 text-blue-600" />
                    Stride
                </div>
            </Link>
            <div className="flex gap-4">
                <Link href="/profile">
                    <Button variant="ghost" className="hover:cursor-pointer">Profile</Button>
                </Link>
                <Link href="/products">
                    <Button variant="ghost" className="hover:cursor-pointer">Shop</Button>
                </Link>
                <Link href="/cart">
                    <Button className="flex items-center gap-2 hover:cursor-pointer" >
                        <ShoppingCart className="h-4 w-4" /> Cart
                    </Button>
                </Link>
            </div>
        </nav>
    );
}