import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import Link from "next/link";



export default function HeroSection() {
  return (
    <section className="flex-1 flex flex-col items-center justify-center text-center px-6 py-16">
      <motion.h1
        className="text-5xl md:text-6xl font-extrabold tracking-tight mb-6"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        Step into the Future of{" "}
        <span className="text-blue-600">Sneaker Style</span>
      </motion.h1>

      <p className="text-lg md:text-xl text-gray-600 mb-8 max-w-2xl">
        Discover sneakers that blend comfort, performance, and style — made
        for urban explorers like you.
      </p>

      <Link href="/login">
        <div className="flex gap-4">
          <Button className="h-14 px-8 text-xl">Login</Button>
        </div>
      </Link>
    </section>
  );
}