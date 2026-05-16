"use client";

import { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/ui/data-table";
import { useShop } from "@/context/ShopProvider";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import Navbar from "@/components/commons/Navbar";
import { DeleteCell } from "./sections/DeleteCell";
import { TermsDialog } from "./sections/TermsDialog";

type Product = {
  name: string;
  price: number;
  img: string;
};

type Promo = {
  code: string;
  desc: string;
  discount?: number;
  freeShip?: boolean;
};

export default function CartModule() {
  const { cart, removeFromCart, checkout } = useShop();
  const [selectedPromos, setSelectedPromos] = useState<Promo[]>([]);

  const columns: ColumnDef<Product>[] = [
    {
      accessorKey: "img",
      header: "Product",
      cell: ({ row }) => (
        <img
          src={row.original.img}
          alt={row.original.name}
          className="w-16 h-16 object-cover rounded-md"
        />
      ),
    },
    { accessorKey: "name", header: "Name" },
    {
      accessorKey: "price",
      header: "Price",
      cell: ({ row }) => `$${row.original.price}`,
    },
    {
      id: "actions",
      header: "Remove",
      cell: ({ row }) => (
        <DeleteCell product={row.original} onRemove={(name: string) => removeFromCart(name)} />
      ),
    },
  ];

  const promos: Promo[] = [
    { code: "WELCOME20", desc: "20% off your first order", discount: 20 },
    { code: "FREESHIP", desc: "Free shipping over $100", freeShip: true },
    { code: "STRIDE10", desc: "10% off all sneakers", discount: 10 },
  ];

  const togglePromo = (promo: Promo) => {
    setSelectedPromos((prev) =>
      prev.some((p) => p.code === promo.code)
        ? prev.filter((p) => p.code !== promo.code)
        : [...prev, promo]
    );
  };

  const handleCheckout = () => {
    if (cart.length === 0) return;
    checkout();
    setSelectedPromos([]);
  };

  return (
    <div>
      {/* Fixed Navbar */}
      <div className="fixed top-0 left-0 right-0 bg-white shadow z-50">
        <Navbar />
      </div>

      {/* Push content below navbar */}
      <div className="px-8 py-20 max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-6">Your Cart</h1>

        <DataTable columns={columns} data={cart} />

        <div className="mt-10">
          <h2 className="text-xl font-bold mb-4">Available Promos</h2>
          <ul className="space-y-2">
            {promos.map((promo, i) => (
              <li
                key={i}
                onClick={() => togglePromo(promo)}
                className={`p-3 border rounded-lg cursor-pointer transition hover:bg-gray-100 ${selectedPromos.some((p) => p.code === promo.code)
                    ? "border-green-500 bg-green-50"
                    : ""
                  }`}
              >
                <span className="font-mono font-bold">{promo.code}</span> —{" "}
                {promo.desc}
              </li>
            ))}
          </ul>
        </div>

        <div className="flex flex-col items-end mt-6 space-y-2">
          <TermsDialog onConfirm={handleCheckout} disabled={cart.length === 0} />
        </div>

      </div>
    </div>
  );
}
