import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Carousel, CarouselContent, CarouselItem, CarouselPrevious, CarouselNext } from "@/components/ui/carousel";
import { motion } from "framer-motion";

export default function FeaturedProductsSection() {
    const products = [
        {
            name: "NovaFlow",
            price: "$109",
            img: "https://cdn.pixabay.com/photo/2020/07/15/15/36/sneaker-5408068_1280.jpg",
            description: "Experience effortless motion with the NovaFlow. These sneakers combine a breathable knit upper with a feather-light sole, giving you the feeling of walking on air. Perfect for daily wear, they offer both style and supreme comfort."
        },
        {
            name: "Zenith",
            price: "$189",
            img: "https://cdn.pixabay.com/photo/2020/08/27/14/29/sneaker-5522169_1280.jpg",
            description: "Reach your peak performance with the Zenith. Designed for serious athletes, this shoe features a responsive cushioning system and a durable, high-grip outsole. Its sleek, modern design ensures you look as good as you perform."
        },
        {
            name: "Stratos",
            price: "$169",
            img: "https://cdn.pixabay.com/photo/2020/07/13/11/30/adidas-5400466_1280.jpg",
            description: "The Stratos takes you to new heights. With a dynamic support frame and a cushioned midsole, this shoe provides stability and energy return. Its bold color scheme makes a statement whether you're on the track or on the street."
        },
        {
            name: "QuantumLeap",
            price: "$179",
            img: "https://cdn.pixabay.com/photo/2024/06/01/06/52/wave-sneakers-8801658_1280.jpg",
            description: "Take a leap into the future with QuantumLeap. Featuring a unique wavy design and advanced sole technology, this sneaker offers unparalleled shock absorption and forward propulsion. It's more than a shoe; it's a piece of kinetic art."
        },
        {
            name: "PulseStride",
            price: "$115",
            img: "https://cdn.pixabay.com/photo/2024/04/21/15/10/ai-generated-8710870_1280.png",
            description: "Feel the rhythm of the city with PulseStride. This versatile sneaker is built for the urban explorer, featuring a robust build and a comfortable footbed that can handle all-day wear. The clean, minimalist design pairs perfectly with any outfit."
        },
        {
            name: "EchoSprint",
            price: "$95",
            img: "https://cdn.pixabay.com/photo/2015/07/13/21/29/footwear-843860_1280.jpg",
            description: "Make a lasting impression with the EchoSprint. Lightweight and agile, these shoes are your go-to for a quick run or a casual outing. The seamless construction and breathable materials ensure your feet stay cool and comfortable, mile after mile."
        }
    ];

    return (
        <section className="py-20 px-4 bg-white">
            <h2 className="text-3xl font-bold text-center mb-12">
                Featured Sneakers
            </h2>
            <div className="max-w-6xl mx-auto">
                <Carousel
                    opts={{
                        align: "start",
                        slidesToScroll: "auto",
                        loop: true,
                    }}
                    className="w-full"
                >
                    <CarouselContent className="-ml-4">
                        {products.map((p, i) => (
                            <CarouselItem key={i} className="pl-4 md:basis-1/2 lg:basis-1/3">
                                <motion.div
                                    initial={{ opacity: 0, y: 30 }}
                                    whileInView={{ opacity: 1, y: 0 }}
                                    transition={{ duration: 0.5, delay: i * 0.1 }}
                                    viewport={{ once: true }}
                                >
                                    <Card className="shadow-md rounded-2xl hover:shadow-lg transition">
                                        <CardHeader>
                                            <img
                                                src={p.img}
                                                alt={p.name}
                                                className="w-full h-56 object-cover rounded-xl"
                                            />
                                        </CardHeader>
                                        <CardContent className="flex flex-col items-center p-4">
                                            <CardTitle className="text-lg mb-2">{p.name}</CardTitle>
                                            {/* <p className="text-gray-600 mb-4">{p.price}</p> */}
                                            <p className="text-gray-600 mb-4">{p.description}</p>
                                        </CardContent>
                                    </Card>
                                </motion.div>
                            </CarouselItem>
                        ))}
                    </CarouselContent>
                    <CarouselPrevious />
                    <CarouselNext />
                </Carousel>
            </div>
        </section>
    );
}