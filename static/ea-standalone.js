(() => {
  console.log("EA: LOADED!");

  function PID(id) {
    // For demo purposes, generate a random hash
    return Math.random().toString(36).substring(2, 15);
  }

  function eaLoader(s, dip, cb) {
    console.log("EA: Load", s);
    var sc = document.createElement("script");
    sc.src = s;
    sc.async = true;
    sc.defer = true;
    if (dip) {
      sc.setAttribute("subscriptions-control", dip);
    }
    if (cb) {
      sc.onload = cb;
    }
    document.head.append(sc);
  }

  // Load EA Assets
  eaLoader("https://accounts.google.com/gsi/client");
  eaLoader("https://news.google.com/swg/js/v1/swg.js", "manual");
  eaLoader("https://news.google.com/swg/js/v1/swg-gaa.js", false, () => {
    console.log("EA: sdk's loaded");
    const urlParams = new URLSearchParams(location.search);
    

    function callSwg(callback) {
      (self.SWG = self.SWG || []).push(callback);
    }

    window.callSwg = callSwg;
    if (PID() || 1 == 1) {
      callSwg((subscriptions) => {
        subscriptions.configure({ paySwgVersion: "2" });
        subscriptions.init("krone.at");
        subscriptions.setOnLoginRequest(function () {
          window.location.href = "https://www.krone.at/#/KRN/login";
        });
        subscriptions.setOnEntitlementsResponse(function (entitlementsPromise) {
          entitlementsPromise.then(function (entitlements) {
            console.log("ON ENTITLEMENTS");
          });
        });
        subscriptions.setOnPaymentResponse(async (paymentResponse) => {
          const response = await paymentResponse;
          var readerID = response.entitlements.entitlements[0].readerId;
          var orderID = JSON.parse(response.purchaseData.data).orderId;
          
          // Call our backend to create the user
          try {
            const result = await fetch('/swg/create-user', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                reader_id: readerID
              })
            });

            if (!result.ok) {
              throw new Error(`HTTP error! status: ${result.status}`);
            }

            const data = await result.json();
            console.log('User created:', data);
            
            // Complete the payment response
            await response.complete();
          } catch (error) {
            console.error('Error creating user:', error);
            // You might want to handle the error differently
            throw error;
          }
        });
      });
    }
  });

})();
