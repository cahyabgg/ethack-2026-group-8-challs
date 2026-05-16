"use client";

import { createContext, useContext, useState, ReactNode } from "react";
import userData from "@/data/user.json";

// ---- Types ----
interface Product {
  name: string;
  price: number;
  img: string;
}

interface CartItem extends Product {
  quantity: number;
}

interface Purchase {
  id: number;
  items: CartItem[];
  total: number;
  date: string;
}

export interface User {
  name: string;
  email: string;
  password: string; // add password for login
}

interface Transaction {
  id: number;
  amount: number;
  date: string;
  category: string;
}

interface ShopContextType {
  user: User | null; // logged-in user
  balance: number;
  transactions: Transaction[];
  cart: CartItem[];
  purchaseHistory: Purchase[];
  totalSpent: number;

  addToCart: (product: Product) => void;
  removeFromCart: (name: string) => void;
  clearCart: () => void;
  checkout: () => void;
  addTransaction: (tx: Transaction) => void;

  login: (email: string, password: string) => boolean;
  logout: () => void;
  isAuthenticated: boolean;
}

// ---- Context ----
const ShopContext = createContext<ShopContextType | undefined>(undefined);

export function ShopProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [balance, setBalance] = useState<number>(100000);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [cart, setCart] = useState<CartItem[]>([]);
  const [purchaseHistory, setPurchaseHistory] = useState<Purchase[]>([]);
  const [totalSpent, setTotalSpent] = useState(0);

  // ---- Auth Methods ----
  const login = (email: string, password: string): boolean => {
    const foundUser = userData.find(
      (u: User) => u.email === email && u.password === password
    );
    if (foundUser) {
      setUser(foundUser);
      return true;
    }
    return false;
  };

  const logout = () => {
    setUser(null);
    setBalance(100000);
    setTransactions([]);
    setCart([]);
    setPurchaseHistory([]);
    setTotalSpent(0);
  };

  // ---- Shop Methods ----
  const addToCart = (product: Product) => {
    setCart((prev) => {
      const existing = prev.find((item) => item.name === product.name);
      if (existing) {
        return prev.map((item) =>
          item.name === product.name
            ? { ...item, quantity: item.quantity + 1 }
            : item
        );
      }
      return [...prev, { ...product, quantity: 1 }];
    });
  };

  const removeFromCart = (name: string) => {
    setCart((prev) => prev.filter((item) => item.name !== name));
  };

  const clearCart = () => setCart([]);

  const checkout = () => {
    if (cart.length === 0) return;

    const total = cart.reduce(
      (sum, item) => sum + item.price * item.quantity * 1000,
      0
    );
    const newPurchase: Purchase = {
      id: purchaseHistory.length + 1,
      items: cart,
      total,
      date: new Date().toISOString().split("T")[0],
    };

    setPurchaseHistory((prev) => [...prev, newPurchase]);
    setTotalSpent((prev) => prev + total);
    setBalance((prev) => prev - total);

    setTransactions((prev) => [
      ...prev,
      {
        id: Date.now(),
        amount: -total,
        date: new Date().toISOString(),
        category: "Purchase",
      },
    ]);

    setCart([]);
  };

  const addTransaction = (tx: Transaction) => {
    setTransactions((prev) => [...prev, tx]);
    setBalance((prev) => prev + tx.amount);
  };

  return (
    <ShopContext.Provider
      value={{
        user,
        balance,
        transactions,
        cart,
        purchaseHistory,
        totalSpent,
        addToCart,
        removeFromCart,
        clearCart,
        checkout,
        addTransaction,
        login,
        logout,
        isAuthenticated: user !== null,
      }}
    >
      {children}
    </ShopContext.Provider>
  );
}

export function useShop() {
  const context = useContext(ShopContext);
  if (!context) throw new Error("useShop must be used within ShopProvider");
  return context;
}
