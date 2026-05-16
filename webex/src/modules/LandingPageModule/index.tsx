"use client";

import { Button } from "@/components/ui/button";
import HeroSection from "./sections/HeroSection";
import FeaturedProductsSection from "./sections/FeaturedProductsSection";
import { useRef } from "react";
import LandingPageNavbar from "./sections/LandingPageNavbar";

export default function LandingModule() {
  const featuredRef = useRef<HTMLDivElement | null>(null);

  const scrollToFeatured = () => {
    featuredRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-b from-white to-gray-50">
      {/* Navbar */}
      <LandingPageNavbar/>

      {/* Hero Section */}
      <HeroSection />

      {/* Call-to-Action */}
      {/* <section className="bg-gradient-to-r from-blue-600 to-blue-500 text-white py-16 text-center px-6">
        <h2 className="text-3xl font-bold mb-4">
          See our featured product selections
        </h2>
        <p className="mb-6 text-lg">Get 20% off your first order.</p>
        <Button size="lg" variant="secondary" onClick={scrollToFeatured}>
          Browse Products
        </Button>
      </section> */}

      {/* Featured Products */}
      {/* <div ref={featuredRef} className="py-10">
        <FeaturedProductsSection />
      </div> */}

      {/* Footer */}
      <footer className="border-t py-6 text-center text-gray-500 text-sm">
        © {new Date().getFullYear()} Stride (Palsu). All rights reserved.
      </footer>
    </div>
  );
}
