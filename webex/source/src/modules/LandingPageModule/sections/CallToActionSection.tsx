import { Button } from "@/components/ui/button";


export function CallToActionSection () {
    return (
      <section className="bg-gradient-to-r from-blue-600 to-blue-500 text-white py-16 text-center px-6">
        <h2 className="text-3xl font-bold mb-4">See our featured product selections</h2>
        <p className="mb-6 text-lg">
          Get 20% off your first order.
        </p>
        <Button size="lg" variant="secondary">
          Subscribe Now
        </Button>
      </section>
    );
}