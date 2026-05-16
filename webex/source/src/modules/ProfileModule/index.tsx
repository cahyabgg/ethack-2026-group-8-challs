"use client";

import { useShop } from "@/context/ShopProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Wallet, User, PlusCircle, History } from "lucide-react";
import Navbar from "@/components/commons/Navbar";

export default function ProfileModule() {
  const { user, balance, transactions, addTransaction } = useShop();

  return (
    <div className="min-h-screen bg-white p-8">
        <Navbar/>
        <br></br>
      <div className="max-w-6xl mx-auto space-y-10">        

        {/* Profile + Balance */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* Profile */}
          <Card className="rounded-2xl shadow-sm border">
            <CardHeader className="flex flex-row items-center gap-2">
              <User className="w-5 h-5 text-blue-600" />
              <CardTitle>User Profile</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-gray-700">
              <p>
                <span className="font-semibold">Name:</span> {user?.name}
              </p>
              <p>
                <span className="font-semibold">Email:</span> {user?.email}
              </p>
            </CardContent>
          </Card>

          {/* Balance */}
          <Card className="rounded-2xl shadow-sm border">
            <CardHeader className="flex flex-row items-center gap-2">
              <Wallet className="w-5 h-5 text-blue-600" />
              <CardTitle>Wallet Balance</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-4xl font-extrabold text-black">
                Rp {balance.toLocaleString("id-ID")}
              </p>
              <Button
                className="mt-6 w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl py-2"
                onClick={() =>
                  addTransaction({
                    id: Date.now(),
                    amount: 50000,
                    date: new Date().toISOString(),
                    category: "Top-up",
                  })
                }
              >
                <PlusCircle className="w-4 h-4" /> Top-up Rp 50.000
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Transactions */}
        <Card className="rounded-2xl shadow-sm border">
          <CardHeader className="flex flex-row items-center gap-2">
            <History className="w-5 h-5 text-gray-600" />
            <CardTitle>Transaction History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr className="bg-gray-100 text-left font-semibold text-gray-700">
                    <th className="p-3 border-b">Amount</th>
                    <th className="p-3 border-b">Date</th>
                    <th className="p-3 border-b">Category</th>
                  </tr>
                </thead>
                <tbody>
                  {transactions.map((tx) => (
                    <tr
                      key={tx.id}
                      className="border-b last:border-none hover:bg-gray-50"
                    >
                      <td
                        className={`p-3 font-semibold ${
                          tx.amount < 0 ? "text-red-600" : "text-green-600"
                        }`}
                      >
                        {tx.amount < 0 ? "-" : "+"}Rp{" "}
                        {Math.abs(tx.amount).toLocaleString("id-ID")}
                      </td>
                      <td className="p-3 text-gray-600">
                        {new Date(tx.date).toLocaleString("id-ID")}
                      </td>
                      <td className="p-3">{tx.category}</td>
                    </tr>
                  ))}
                  {transactions.length === 0 && (
                    <tr>
                      <td
                        colSpan={3}
                        className="p-4 text-center text-gray-500 italic"
                      >
                        No transactions yet
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
