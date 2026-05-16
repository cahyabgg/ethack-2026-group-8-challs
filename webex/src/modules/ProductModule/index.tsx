"use client";

import Navbar from "@/components/commons/Navbar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Carousel, CarouselContent, CarouselItem, CarouselNext, CarouselPrevious } from "@/components/ui/carousel";
import { useShop } from "@/context/ShopProvider";
import { motion } from "framer-motion";
import { ShoppingCart } from "lucide-react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import * as React from "react";

export default function ProductsModule() {
  const { addToCart } = useShop();
  const router = useRouter();

  const products = [
    { name: "AirStride X", price: 129, img: "https://images.unsplash.com/photo-1603787081207-362bcef7c144?w=600&auto=format&fit=crop&q=60" },
    { name: "UrbanFlex", price: 149, img: "https://images.unsplash.com/photo-1560769629-975ec94e6a86?w=600&auto=format&fit=crop&q=60" },
    { name: "CloudStep", price: 99, img: "https://images.unsplash.com/flagged/photo-1556637640-2c80d3201be8?w=600&auto=format&fit=crop&q=60" },
    { name: "StreetRunner", price: 159, img: "https://images.unsplash.com/photo-1549298916-b41d501d3772?w=600&auto=format&fit=crop&q=60" },
    { name: "FlexLite", price: 119, img: "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=600&auto=format&fit=crop&q=60" },
    { name: "NightSprint", price: 139, img: "https://images.unsplash.com/photo-1515955656352-a1fa3ffcd111?w=600&auto=format&fit=crop&q=60&ixlib=rb-4.1.0" },
    { name: "PulseBoost", price: 179, img: "https://images.unsplash.com/photo-1724921195449-e9c02955be37?w=600&auto=format&fit=crop&q=60&ixlib=rb-4.1.0" },
    { name: "UrbanEdge", price: 109, img: "https://images.unsplash.com/photo-1605348532760-6753d2c43329?w=600&auto=format&fit=crop&q=60&ixlib=rb-4.1.0" },
    { name: "CloudNova", price: 189, img: "https://images.unsplash.com/photo-1595950653106-6c9ebd614d3a?w=600&auto=format&fit=crop&q=60&ixlib=rb-4.1.0" },
  ];

  const [emblaApi, setEmblaApi] = React.useState<any>(null);

  React.useEffect(() => {
    if (!emblaApi) return;
    const interval = setInterval(() => {
      emblaApi.scrollNext();
    }, 2000); 
    return () => clearInterval(interval);
  }, [emblaApi]);

  return (
    <section className="px-8 bg-white">
      <Navbar />

      <h2 className="text-3xl font-bold text-center mb-8">All Sneakers</h2>

      <div className="max-w-3xl mx-auto">
        <Carousel className="w-full" setApi={setEmblaApi}
        opts={{
            loop: true
        }}>
          <CarouselContent>
            {products.map((p, i) => (
              <CarouselItem key={i} className="basis-full">
                <motion.div
                  initial={{ opacity: 0, y: 24 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.4 }}
                  viewport={{ once: true }}
                >
                  <Card className="shadow-md rounded-2xl hover:shadow-lg transition">
                    <CardHeader>
                      <img
                        src={p.img}
                        alt={p.name}
                        className="w-full h-72 object-cover rounded-xl"
                      />
                    </CardHeader>
                    <CardContent className="flex flex-col items-center">
                      <CardTitle className="text-lg mb-2">{p.name}</CardTitle>
                      <p className="text-gray-600 mb-4">Rp {p.price}.000</p>
                      <Button
                        className="w-full hover:cursor-pointer"
                        onClick={() => {
                          addToCart(p);
                          toast.success(`${p.name} added to cart!`, {
                            description: "Check your cart to review items.",
                            action: { label: "View Cart", onClick: () => router.push("/cart") },
                          });
                        }}
                      >
                        <ShoppingCart className="mr-2 h-4 w-4" /> Add to Cart
                      </Button>
                    </CardContent>
                  </Card>
                </motion.div>
              </CarouselItem>
            ))}
          </CarouselContent>

          <div className="relative mt-4 flex items-center justify-center gap-4">
            <CarouselPrevious className="static translate-x-0 translate-y-0" />
            <CarouselNext className="static translate-x-0 translate-y-0" />
          </div>
        </Carousel>
      </div>
    </section>
  );
}
