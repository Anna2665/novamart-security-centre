import { AccountPage } from "./Account";
import { CartPage } from "./Cart";
import { CheckoutPage, SignInPage } from "./Checkout";
import { Home } from "./Home";
import { OrderPage, OrdersPage } from "./Orders";
import { ProductPage } from "./Product";

/** Storefront router: maps the first URL segments to a page. Exported as `Account` only to keep App's import list short. */
export function Storefront({ parts }: { parts: string[] }) {
  const [a, b] = parts;
  const arg = b ? decodeURIComponent(b) : "";
  switch (a) {
    case "search": return <Home q={arg} />;
    case "category": return <Home category={arg} />;
    case "product": return <ProductPage id={Number(arg) || 0} />;
    case "cart": return <CartPage />;
    case "checkout": return <CheckoutPage />;
    case "orders": return arg ? <OrderPage no={arg} /> : <OrdersPage />;
    case "account": return <AccountPage />;
    case "signin": return <SignInPage />;
    case "register": return <SignInPage initialMode="register" />;
    default: return <Home />;
  }
}
